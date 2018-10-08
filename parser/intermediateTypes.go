package parser

import (
	"bytes"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/shankarapailoor/trace2syz/utils"
	"strconv"
)

type Operation int

const (
	ORop       = iota //OR = |
	ANDop             //AND = &
	XORop             //XOR = ^
	NOTop             //NOT = !
	LSHIFTop          //LSHIFT = <<
	RSHIFTop          //RSHIFT = >>
	ONESCOMPop        //ONESCOMP = ~
	TIMESop           //TIMES = *
	LANDop            //LAND = &&
	LORop             //LOR = ||
	LEQUALop          //LEQUAL = ==

	exprTypeName    string = "Expression Type"
	groupTypeName   string = "Group Type"
	callTypeName    string = "Call Type"
	bufferTypeName  string = "Buffer Type"
	pointerTypeName string = "Pointer Type"
	flagTypeName    string = "Flag Type"
)

//TraceTree struct contains intermediate representation of trace
//If a trace is multiprocess it constructs a trace for each type
type TraceTree struct {
	TraceMap map[int64]*Trace
	Ptree    map[int64][]int64
	RootPid  int64
	Filename string
}

//NewTraceTree initializes a TraceTree
func NewTraceTree() (tree *TraceTree) {
	tree = &TraceTree{
		TraceMap: make(map[int64]*Trace),
		Ptree:    make(map[int64][]int64),
		RootPid:  -1,
	}
	return
}

func (tree *TraceTree) contains(pid int64) bool {
	if _, ok := tree.TraceMap[pid]; ok {
		return true
	}
	return false
}

func (tree *TraceTree) add(call *Syscall) *Syscall {
	if tree.RootPid < 0 {
		tree.RootPid = call.Pid
	}
	if !call.Resumed {
		if !tree.contains(call.Pid) {
			tree.TraceMap[call.Pid] = newTrace()
			tree.Ptree[call.Pid] = make([]int64, 0)
		}
	}
	c := tree.TraceMap[call.Pid].add(call)
	if c.CallName == "clone" && !c.Paused {
		tree.Ptree[c.Pid] = append(tree.Ptree[c.Pid], c.Ret)
	}
	return c
}

func (tree *TraceTree) string() string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("Root: %d\n", tree.RootPid))
	buf.WriteString(fmt.Sprintf("Pids: %d\n", len(tree.TraceMap)))
	return buf.String()
}

//Trace is just a list of system calls
type Trace struct {
	Calls []*Syscall
}

//newTrace initializes a new trace
func newTrace() (trace *Trace) {
	trace = &Trace{Calls: make([]*Syscall, 0)}
	return
}

func (trace *Trace) add(call *Syscall) (ret *Syscall) {
	if call.Resumed {
		lastCall := trace.Calls[len(trace.Calls)-1]
		lastCall.Args = append(lastCall.Args, call.Args...)
		lastCall.Paused = false
		lastCall.Ret = call.Ret
		ret = lastCall
	} else {
		trace.Calls = append(trace.Calls, call)
		ret = call
	}
	return
}

//IrType is the intermediate representation of the strace output
//Every argument of a system call should be represented in an intermediate type
type IrType interface {
	Name() string
	String() string
}

//Syscall struct is the IR type for any system call
type Syscall struct {
	CallName string
	Args     []IrType
	Pid      int64
	Ret      int64
	Cover    []uint64
	Paused   bool
	Resumed  bool
}

//NewSyscall - constructor
func NewSyscall(pid int64, name string, args []IrType, ret int64, paused, resumed bool) (sys *Syscall) {
	return &Syscall{
		CallName: name,
		Args:     args,
		Pid:      pid,
		Ret:      ret,
		Paused:   paused,
		Resumed:  resumed,
	}
}

//String
func (s *Syscall) String() string {
	buf := new(bytes.Buffer)

	fmt.Fprintf(buf, "Pid: %d-", s.Pid)
	fmt.Fprintf(buf, "Name: %s-", s.CallName)
	for _, typ := range s.Args {
		buf.WriteString("-")
		buf.WriteString(typ.String())
		buf.WriteString("-")
	}
	buf.WriteString(fmt.Sprintf("-Ret: %d\n", s.Ret))
	return buf.String()
}

//Given a Syzkaller type, we generate a default intermediate type.
func GenDefaultIrType(syzType prog.Type) IrType {
	switch a := syzType.(type) {
	case *prog.StructType:
		straceFields := make([]IrType, len(a.Fields))
		for i := 0; i < len(straceFields); i++ {
			straceFields[i] = GenDefaultIrType(a.Fields[i])
		}
		return newGroupType(straceFields)
	case *prog.ArrayType:
		straceFields := make([]IrType, 1)
		straceFields[0] = GenDefaultIrType(a.Type)
		return newGroupType(straceFields)
	case *prog.ConstType, *prog.ProcType, *prog.LenType, *prog.FlagsType, *prog.IntType:
		return NewIntsType([]int64{0})
	case *prog.PtrType:
		return NewPointerType(0, GenDefaultIrType(a.Type))
	case *prog.UnionType:
		return GenDefaultIrType(a.Fields[0])
	default:
		log.Fatalf("Unsupported syz type for generating default strace type: %s", syzType.Name())
	}
	return nil
}

//Represents arguments that are expanded by strace into calls
//E.g. inet_addr("127.0.0.1")
type Call struct {
	CallName string
	Args     []IrType
}

func newCallType(name string, args []IrType) *Call {
	return &Call{CallName: name, Args: args}
}

//Implements Name()
func (c *Call) Name() string {
	return callTypeName
}

//Implements String()
func (c *Call) String() string {
	buf := new(bytes.Buffer)
	buf.WriteString("Name: " + c.CallName + "\n")
	for _, arg := range c.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

//Arrays and Structs
type GroupType struct {
	Elems []IrType
	Len   int
}

func newGroupType(elems []IrType) (typ *GroupType) {
	return &GroupType{Elems: elems, Len: len(elems)}
}

//Implements Name()
func (a *GroupType) Name() string {
	return groupTypeName
}

//Implements String()
func (a *GroupType) String() string {
	var buf bytes.Buffer

	buf.WriteString("[")
	for _, elem := range a.Elems {
		buf.WriteString(elem.String())
		buf.WriteString(",")
	}
	buf.WriteString("]")
	return buf.String()
}

//Field of a struct e.g. name = "Shankara"
type Field struct {
	Key string
	Val IrType
}

func newField(key string, val IrType) *Field {
	return &Field{Key: key, Val: val}
}

func (f *Field) Name() string {
	return "Field Type"
}

func (f *Field) String() string {
	return f.Val.String()
}

//Represents Ints, Flags,Arithmetic expressions
type Expression interface {
	IrType
	Eval(*prog.Target) uint64
}

type expressionCommon struct {
}

func (e *expressionCommon) Name() string {
	return exprTypeName
}

type binOp struct {
	expressionCommon
	leftOp  Expression
	op      Operation
	rightOp Expression
}

func newBinop(leftOperand, rightOperand IrType, Op Operation) *binOp {
	return &binOp{leftOp: leftOperand.(Expression), rightOp: rightOperand.(Expression), op: Op}
}

//Implements Eval()
func (b *binOp) Eval(target *prog.Target) uint64 {
	op1Eval := b.leftOp.Eval(target)
	op2Eval := b.rightOp.Eval(target)
	switch b.op {
	case ANDop:
		return op1Eval & op2Eval
	case ORop:
		return op1Eval | op2Eval
	case XORop:
		return op1Eval ^ op2Eval
	case LSHIFTop:
		return op1Eval << op2Eval
	case RSHIFTop:
		return op1Eval >> op2Eval
	case TIMESop:
		return op1Eval * op2Eval
	default:
		log.Fatalf("Unable to handle op: %d", b.op)
		return 0
	}
}

//Implements String()
func (b *binOp) String() string {
	return fmt.Sprintf("op1: %s op2: %s, operand: %v\n", b.leftOp.String(), b.rightOp.String(), b.op)
}

type unOp struct {
	expressionCommon
	op      Operation
	operand Expression
}

func newUnop(operand IrType, op Operation) *unOp {
	return &unOp{op: op, operand: operand.(Expression)}
}

//Implements Eval()
func (u *unOp) Eval(target *prog.Target) uint64 {
	opEval := u.operand.Eval(target)
	switch u.op {
	case ONESCOMPop:
		return ^opEval
	default:
		log.Fatalf("Unsupported Unop Op: %d", u.op)
	}
	return 0
}

//Implements String()
func (u *unOp) String() string {
	return fmt.Sprintf("op1: %v operand: %v\n", u.operand, u.op)
}

//Represents cases where strace shows the before system call and after
//E.g. <... getsockname resumed> {sa_family=AF_INET6,..., sin6_scope_id=0}, [112->28]
type DynamicType struct {
	BeforeCall Expression
	AfterCall  Expression
}

func newDynamicType(before, after IrType) *DynamicType {
	return &DynamicType{BeforeCall: before.(Expression), AfterCall: after.(Expression)}
}

//Implements String()
func (d *DynamicType) String() string {
	return d.BeforeCall.String()
}

//Implements Name()
func (d *DynamicType) Name() string {
	return "Dynamic Type"
}

//Meant for cases where strace produces macros like KERNEL_VERSION
type macroType struct {
	expressionCommon
	MacroName string
	Args      []IrType
}

func newMacroType(name string, args []IrType) *macroType {
	return &macroType{MacroName: name, Args: args}
}

//Implements String()
func (m *macroType) String() string {
	var buf bytes.Buffer

	buf.WriteString("Name: " + m.MacroName + "\n")
	for _, arg := range m.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

//Implements Eval()
func (m *macroType) Eval(target *prog.Target) uint64 {
	switch m.MacroName {
	case "KERNEL_VERSION":
		a1 := m.Args[0].(Expression)
		a2 := m.Args[1].(Expression)
		a3 := m.Args[2].(Expression)
		return (a1.Eval(target) << 16) + (a2.Eval(target) << 8) + a3.Eval(target)
	default:
		log.Fatalf("Unsupported Macro: %s", m.MacroName)
	}
	return 0
}

//Garbage type used to parse content inside of ending parenthesis from strace
//E.g. access(....) = -1 ENOENT (No such file or directory). The stuff in the ending parenthesis
//will get parsed into this type
type parenthetical struct {
	tmp string
}

func newParenthetical() *parenthetical {
	return &parenthetical{tmp: "tmp"}
}

//Contains strings
type BufferType struct {
	Val string
}

func newBufferType(val string) *BufferType {
	return &BufferType{Val: val}
}

//Implements Name()
func (b *BufferType) Name() string {
	return bufferTypeName
}

//Implements String()
func (b *BufferType) String() string {
	return fmt.Sprintf("Buffer: %s with length: %d\n", b.Val, len(b.Val))
}

type intType struct {
	Val int64
}

func newIntType(val int64) (typ *intType) {
	return &intType{Val: val}
}
func (i *intType) eval(target *prog.Target) uint64 {
	return uint64(i.Val)
}

func (i *intType) Name() string {
	return "Int Type"
}

func (i *intType) String() string {
	return strconv.Itoa(int(i.Val))
}

//Contains set of Flags. Most of the time will contain just 1 element
type Flags []*flagType

//Contains set of Ints. Most of the time will contain just 1 element
type Ints []*intType

func NewIntsType(vals []int64) Ints {
	var ints []*intType
	for _, v := range vals {
		ints = append(ints, newIntType(v))
	}
	return ints
}

//Implements Eval()
func (f Flags) Eval(target *prog.Target) uint64 {
	if len(f) > 1 {
		//It isn't safe to evaluate flags with more than one element.
		//For example we can have a system call like rt_sigprocmask with argument
		// [RTMIN RT_1]. Simply Or'ing the values is not correct. Right now we allow
		// more than one just to parse these calls.
		log.Fatalf("Cannot evaluate flags with more than one element")
	}
	if len(f) == 1 {
		return f[0].eval(target)
	}
	return 0
}

//Implements Name()
func (f Flags) Name() string {
	return exprTypeName
}

//Implements String()
func (f Flags) String() string {
	if len(f) == 1 {
		return f[0].String()
	}
	return ""
}

//Implements Eval()
func (i Ints) Eval(target *prog.Target) uint64 {
	if len(i) > 1 {
		//We need to handle this case by case. We allow more than one elemnt
		//just to properly parse the traces
		log.Fatalf("Cannot evaluate Ints with more than one element")
	}
	if len(i) == 1 {
		return i[0].eval(target)
	}
	return 0
}

//Implements Name()
func (i Ints) Name() string {
	return exprTypeName
}

//Implements String()
func (i Ints) String() string {
	if len(i) == 1 {
		return i[0].String()
	}
	return ""
}

type flagType struct {
	Val string
}

func newFlagType(val string) (typ *flagType) {
	return &flagType{Val: val}
}

func (f *flagType) eval(target *prog.Target) uint64 {
	if val, ok := target.ConstMap[f.String()]; ok {
		return val
	}
	if val, ok := utils.SpecialConsts[f.String()]; ok {
		return val
	}
	log.Fatalf("Failed to eval flag: %s\n", f.String())
	return 0
}

//Implements Name()
func (f *flagType) Name() string {
	return flagTypeName
}

//Implements String()
func (f *flagType) String() string {
	return f.Val
}

//Captures pointer types
type PointerType struct {
	Address uint64
	Res     IrType
}

func NewPointerType(addr uint64, res IrType) *PointerType {
	return &PointerType{Res: res, Address: addr}
}

func nullPointer() (typ *PointerType) {
	return &PointerType{Res: newBufferType(""), Address: 0}
}

func (p *PointerType) IsNull() bool {
	return p.Address == 0
}

//Implements Name()
func (p *PointerType) Name() string {
	return pointerTypeName
}

//Implements String()
func (p *PointerType) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "Address: %d\n", p.Address)
	fmt.Fprintf(buf, "Res: %s\n", p.Res.String())
	return buf.String()
}
