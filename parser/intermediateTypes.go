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
	arrayTypeName   string = "Array Type"
	structTypeName  string = "Struct Type"
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

func (tree *TraceTree) Contains(pid int64) bool {
	if _, ok := tree.TraceMap[pid]; ok {
		return true
	}
	return false
}

func (tree *TraceTree) Add(call *Syscall) *Syscall {
	if tree.RootPid < 0 {
		tree.RootPid = call.Pid
	}
	if !call.Resumed {
		if !tree.Contains(call.Pid) {
			tree.TraceMap[call.Pid] = newTrace()
			tree.Ptree[call.Pid] = make([]int64, 0)
		}
	}
	c := tree.TraceMap[call.Pid].Add(call)
	if c.CallName == "clone" && !c.Paused {
		tree.Ptree[c.Pid] = append(tree.Ptree[c.Pid], c.Ret)
	}
	return c
}

func (tree *TraceTree) String() string {
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

func (trace *Trace) Add(call *Syscall) (ret *Syscall) {
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
	sys = new(Syscall)
	sys.CallName = name
	sys.Args = args
	sys.Pid = pid
	sys.Ret = ret
	sys.Paused = paused
	sys.Resumed = resumed
	return
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

type IrType interface {
	Name() string
	String() string
}

func GenDefaultIrType(syzType prog.Type) IrType {
	switch a := syzType.(type) {
	case *prog.StructType:
		straceFields := make([]IrType, len(a.Fields))
		for i := 0; i < len(straceFields); i++ {
			straceFields[i] = GenDefaultIrType(a.Fields[i])
		}
		return NewStructType(straceFields)
	case *prog.ArrayType:
		straceFields := make([]IrType, 1)
		straceFields[0] = GenDefaultIrType(a.Type)
		return NewArrayType(straceFields)
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

type Call struct {
	CallName string
	Args     []IrType
}

func newCallType(name string, args []IrType) (typ *Call) {
	typ = new(Call)
	typ.CallName = name
	typ.Args = args
	return
}

func (c *Call) Name() string {
	return callTypeName
}

func (c *Call) String() string {
	buf := new(bytes.Buffer)
	buf.WriteString("Name: " + c.CallName + "\n")
	for _, arg := range c.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

type StructType struct {
	Fields []IrType
}

func NewStructType(types []IrType) (typ *StructType) {
	typ = new(StructType)
	typ.Fields = types
	return
}

func (s *StructType) Name() string {
	return structTypeName
}

func (s *StructType) String() string {
	var buf bytes.Buffer

	buf.WriteString("{")
	for _, field := range s.Fields {
		buf.WriteString(field.String())
		buf.WriteString(",")
	}
	buf.WriteString("}")
	return buf.String()
}

type ArrayType struct {
	Elems []IrType
	Len   int
}

func NewArrayType(elems []IrType) (typ *ArrayType) {
	typ = new(ArrayType)
	typ.Elems = elems
	typ.Len = len(elems)
	return
}

func (a *ArrayType) Name() string {
	return arrayTypeName
}

func (a *ArrayType) String() string {
	var buf bytes.Buffer

	buf.WriteString("[")
	for _, elem := range a.Elems {
		buf.WriteString(elem.String())
		buf.WriteString(",")
	}
	buf.WriteString("]")
	return buf.String()
}

type Field struct {
	Key string
	Val IrType
}

func newField(key string, val IrType) (f *Field) {
	f = new(Field)
	f.Key = key
	f.Val = val
	return
}

func (f *Field) Name() string {
	return "Field Type"
}

func (f *Field) String() string {
	return f.Val.String()
}

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
	LeftOp  Expression
	Op      Operation
	RightOp Expression
}

func newBinop(leftOperand, rightOperand IrType, Op Operation) *binOp {
	b := new(binOp)
	b.LeftOp = leftOperand.(Expression)
	b.RightOp = rightOperand.(Expression)
	b.Op = Op
	return b
}

func (b *binOp) Eval(target *prog.Target) uint64 {
	op1Eval := b.LeftOp.Eval(target)
	op2Eval := b.RightOp.Eval(target)
	switch b.Op {
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
		log.Fatalf("Unable to handle op: %d", b.Op)
		return 0
	}
}

func (b *binOp) String() string {
	return fmt.Sprintf("op1: %s op2: %s, operand: %v\n", b.LeftOp.String(), b.RightOp.String(), b.Op)
}

type unOp struct {
	expressionCommon
	Op      Operation
	Operand Expression
}

func newUnop(operand IrType, Op Operation) *unOp {
	u := new(unOp)
	u.Op = Op
	u.Operand = operand.(Expression)
	return u
}

func (u *unOp) Eval(target *prog.Target) uint64 {
	opEval := u.Operand.Eval(target)
	switch u.Op {
	case ONESCOMPop:
		return ^opEval
	default:
		log.Fatalf("Unsupported Unop Op: %d", u.Op)
	}
	return 0
}

func (u *unOp) String() string {
	return fmt.Sprintf("op1: %v operand: %v\n", u.Operand, u.Op)
}

func (u *unOp) Name() string {
	return "Unop"
}

type DynamicType struct {
	BeforeCall Expression
	AfterCall  Expression
}

func newDynamicType(before, after IrType) *DynamicType {
	return &DynamicType{BeforeCall: before.(Expression), AfterCall: after.(Expression)}
}

func (d *DynamicType) String() string {
	return d.BeforeCall.String()
}

func (d *DynamicType) Name() string {
	return "Dynamic Type"
}

type macroType struct {
	expressionCommon
	MacroName string
	Args      []IrType
}

func newMacroType(name string, args []IrType) (typ *macroType) {
	typ = new(macroType)
	typ.MacroName = name
	typ.Args = args
	return
}

func (m *macroType) String() string {
	var buf bytes.Buffer

	buf.WriteString("Name: " + m.MacroName + "\n")
	for _, arg := range m.Args {
		buf.WriteString("Arg: " + arg.Name() + "\n")
	}
	return buf.String()
}

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

type parenthetical struct {
	tmp string
}

type BufferType struct {
	Val string
}

func newParenthetical() *parenthetical {
	return &parenthetical{tmp: "tmp"}
}

type intType struct {
	Val int64
}

type Flags []*flagType

type Ints []*intType

func NewIntsType(vals []int64) Ints {
	ints := make([]*intType, 0)
	for _, v := range vals {
		ints = append(ints, newIntType(v))
	}
	return ints
}

func newIntType(val int64) (typ *intType) {
	typ = new(intType)
	typ.Val = val
	return
}

func (i *intType) Eval(target *prog.Target) uint64 {
	return uint64(i.Val)
}

func (i *intType) Name() string {
	return "Int Type"
}

func (i *intType) String() string {
	return strconv.Itoa(int(i.Val))
}

func (f Flags) Eval(target *prog.Target) uint64 {
	if len(f) > 1 {
		//It isn't safe to evaluate flags with more than one element.
		//For example we can have a system call like rt_sigprocmask with argument
		// [RTMIN RT_1]. Simply Or'ing the values is not correct. Right now we allow
		// more than one just to parse these calls.
		log.Fatalf("Cannot evaluate flags with more than one element")
	}
	if len(f) == 1 {
		return f[0].Eval(target)
	}
	return 0
}

func (f Flags) Name() string {
	return exprTypeName
}

func (f Flags) String() string {
	if len(f) == 1 {
		return f[0].String()
	}
	return ""
}

func (i Ints) Eval(target *prog.Target) uint64 {
	if len(i) > 1 {
		//We need to handle this case by case. We allow more than one elemnt
		//just to properly parse the traces
		log.Fatalf("Cannot evaluate Ints with more than one element")
	}
	if len(i) == 1 {
		return i[0].Eval(target)
	}
	return 0
}

func (i Ints) Name() string {
	return exprTypeName
}

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
	typ = new(flagType)
	typ.Val = val
	return
}

func (f *flagType) Eval(target *prog.Target) uint64 {
	if val, ok := target.ConstMap[f.String()]; ok {
		return val
	}
	if val, ok := utils.SpecialConsts[f.String()]; ok {
		return val
	}
	log.Fatalf("Failed to eval flag: %s\n", f.String())
	return 0
}

func (f *flagType) Name() string {
	return flagTypeName
}

func (f *flagType) String() string {
	return f.Val
}

func newBufferType(val string) (typ *BufferType) {
	typ = new(BufferType)
	typ.Val = val
	return
}

func (b *BufferType) Name() string {
	return bufferTypeName
}

func (b *BufferType) String() string {
	return fmt.Sprintf("Buffer: %s with length: %d\n", b.Val, len(b.Val))
}

type PointerType struct {
	Address uint64
	Res     IrType
}

func NewPointerType(addr uint64, res IrType) (typ *PointerType) {
	typ = new(PointerType)
	typ.Res = res
	typ.Address = addr
	return
}

func nullPointer() (typ *PointerType) {
	typ = new(PointerType)
	typ.Address = 0
	typ.Res = newBufferType("")
	return
}

func (p *PointerType) IsNull() bool {
	return p.Address == 0
}

func (p *PointerType) Name() string {
	return pointerTypeName
}

func (p *PointerType) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "Address: %d\n", p.Address)
	fmt.Fprintf(buf, "Res: %s\n", p.Res.String())

	return buf.String()
}
