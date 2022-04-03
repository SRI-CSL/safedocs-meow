/*
 * Copyright River Loop Security 2020-2022 All Rights Reserved.
 * This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
 */

package main

import (
	"debug/dwarf"
	"debug/elf"
	"log"
	"fmt"
	"os"
)

type Structure struct {
	Name    string
	Size    int64
	Members []Member
}

type Member struct {
	Name string
	Size int64
	Type string
	Offset int64
}

func printEntry(entry *dwarf.Entry) {
	log.Printf("Tag: %s", entry.Tag)
	log.Printf("Offset: %d", entry.Offset)
	for _, field := range entry.Field {
		log.Printf("\t%s: %v", field.Attr, field.Val)
	}
}

type StructureStack []*Structure

func (stk StructureStack) push(s *Structure) StructureStack {
	return append(stk, s)
}

func (stk StructureStack) pop() (StructureStack, *Structure) {
	if len(stk) == 0 {
		return stk, nil
	}
	idx := len(stk) - 1
	last := stk[idx]
	return stk[:idx], last
}

func (stk StructureStack) peek() *Structure {
	idx := len(stk) - 1
	if idx < 0 {
		log.Fatal("Peek called with empty stack!!!")
	}
	return stk[idx]
}

func handleStruct(e *dwarf.Entry) *Structure {
	nf := e.AttrField(dwarf.AttrName)
	name := "[unknown]"
	if nf != nil {
		name = nf.Val.(string)
	}

	sf := e.AttrField(dwarf.AttrByteSize)
	if sf == nil {
		return nil
	}

	bs := sf.Val.(int64)

	s := &Structure{
		Name: name,
		Size: bs,
	}

	return s
}

func handleMember(d *dwarf.Data, s *Structure, e *dwarf.Entry) {
	nf := e.AttrField(dwarf.AttrName)
	name := "[unknown]"
	if nf != nil {
		name = nf.Val.(string)
	}

	tf := e.AttrField(dwarf.AttrType)
	if tf == nil || tf.Class != dwarf.ClassReference {
		// log.Println("nil type field or non reference class (1)")
		return
	}

	lf := e.AttrField(dwarf.AttrDataMemberLoc)
	if lf == nil || lf.Class != dwarf.ClassConstant {
		// log.Println("nil type field or non constant class (2)")
		return
	}
	loc := lf.Val.(int64)

	toff := tf.Val.(dwarf.Offset)
	t, err := d.Type(toff)
	if err != nil {
		log.Println(err, s.Name)
		return
	}

	m := Member{
		Name: name,
		Size: t.Common().ByteSize,
		Type: t.String(),
		Offset: loc,
	}

	s.Members = append(s.Members, m)
}

func getType(d *dwarf.Data, e *dwarf.Entry) dwarf.Type {
	v := e.Val(dwarf.AttrType)
	if v == nil {
		return nil
	}
	toff := v.(dwarf.Offset)
	t, err := d.Type(toff)
	if err != nil {
		log.Fatal(err)
	}
	return t
}

type FileLine [2]int

type Signature struct {
	Address int
	Name string
	Type string
	ParamTypes []string
	ParamNames []string
}

type SignatureStack []*Signature

func (stk SignatureStack) push(s *Signature) SignatureStack {
	return append(stk, s)
}

func (stk SignatureStack) pop() (SignatureStack, *Signature) {
	if len(stk) == 0 {
		return stk, nil
	}
	idx := len(stk) - 1
	last := stk[idx]
	return stk[:idx], last
}

func (stk SignatureStack) peek() *Signature {
	idx := len(stk) - 1
	if idx < 0 {
		log.Fatal("Peek called with empty stack!!!")
	}
	return stk[idx]
}

func (s Signature) String() string {
	if len(s.ParamTypes) != len(s.ParamNames) {
		log.Fatal("sig: len != len")
	}

	out := fmt.Sprintf("%s %s(", s.Type, s.Name)
	for i := range s.ParamTypes {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s %s", s.ParamTypes[i], s.ParamNames[i])
	}
	out += ")"
	return out
}

type Control int
const (
	NONE = iota
	COMPILE_UNIT 
	STRUCTURE
	SIGNATURE
)

type ControlStack []Control

func (stk ControlStack) push(s Control) ControlStack {
	return append(stk, s)
}

func (stk ControlStack) pop() (ControlStack, Control) {
	if len(stk) == 0 {
		return stk, NONE
	}
	idx := len(stk) - 1
	last := stk[idx]
	return stk[:idx], last
}

func (stk ControlStack) peek() Control {
	idx := len(stk) - 1
	if idx < 0 {
		log.Fatal("Peek called with empty stack!!!")
	}
	return stk[idx]
}

type CompileUnit struct {
	FileNameToIndex map[string]int
	FileLineToPC map[FileLine]uint64
	DwarfToSignature map[int]Signature
}

func NewCompileUnit() *CompileUnit {
	return &CompileUnit{
		FileNameToIndex: make(map[string]int),
		FileLineToPC: make(map[FileLine]uint64),
		DwarfToSignature: make(map[int]Signature),
	}
}

func NewFileLine(file, line int) FileLine {
	return [2]int{file, line}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile) 

	if len(os.Args) < 2 {
		log.Fatalf("USAGE: %s filename", os.Args[0])
	}

	fname := os.Args[1]
	f, err := elf.Open(fname)
	if err != nil {
		log.Fatal(err)
	}

	d, err := f.DWARF()
	if err != nil {
		log.Fatal(err)
	}

	r := d.Reader()
	sts := StructureStack{}
	// sgs := SignatureStack{}
	cs := ControlStack{}
	var cu *CompileUnit

	outs := []*Structure{}
	for entry, err := r.Next(); entry != nil; entry, err = r.Next() {
		if err != nil {
			log.Println(err)
			continue
		}

		switch entry.Tag {
		case 0:
			var ctrl Control
			cs, ctrl = cs.pop()
			switch ctrl {
			case STRUCTURE:
				var st *Structure
				sts, st = sts.pop()
				if st != nil {
					// log.Println("out")
					outs = append(outs, st)
				}
			case SIGNATURE:
			case COMPILE_UNIT:
				cu = nil
			}
			// log.Println("=== END", len(stack))
		case dwarf.TagCompileUnit:
			log.Println("cucu", entry.Val(dwarf.AttrName).(string))
			printEntry(entry)
			lr, err := d.LineReader(entry)
			if err != nil {
				log.Fatal(err)
			}

			cu = NewCompileUnit()

			for i, file := range lr.Files() {
				if file == nil {
					continue
				}
				cu.FileNameToIndex[file.Name] = i
			}

			le := &dwarf.LineEntry{}
			for err = lr.Next(le); le != nil; err = lr.Next(le) {
				if err != nil {
					log.Println(err)
					break
				}
				fIdx, ok := cu.FileNameToIndex[le.File.Name]
				if !ok {
					log.Println("file not found in index", le.File.Name)
					continue
				}
				fln := NewFileLine(fIdx, le.Line)
				cu.FileLineToPC[fln] = le.Address
			}

			cs = cs.push(COMPILE_UNIT)
		case dwarf.TagClassType:
			fallthrough
		case dwarf.TagStructType:
			printEntry(entry)
			curr := handleStruct(entry)
			if curr != nil {
				sts = sts.push(curr)
			}
			cs = cs.push(STRUCTURE)
		case dwarf.TagMember:
			if len(sts) == 0 {
				continue
			}
			printEntry(entry)
			handleMember(d, sts.peek(), entry)
		case dwarf.TagSubprogram:
			fmt.Println("subsub")
			printEntry(entry)
			r, err := d.Ranges(entry)
			if err != nil {
				log.Println(err)
			}

			spec := entry.Val(AttrSpecificatoin)
			if spec != nil {

			} else {
				
			}
			t := getType(d, entry)
			if t != nil {
				fmt.Println(t.String())
			}
			fmt.Println("ranges", r)
			cs = cs.push(SIGNATURE)
		case dwarf.TagFormalParameter:
			fmt.Println("formalparam")
			printEntry(entry)
			t := getType(d, entry)
			if t != nil {
				fmt.Println(t.String())
			}
		default:
			r.SkipChildren()
			continue
		}
	}


	fmt.Println("t/name/size")
	fmt.Println("m/off/name/size[/h:type]")
	fmt.Println(len(outs))
	for _, s := range outs {
		if s.Size < 2 || s.Name == "[unknown]" {
			continue
		}
		// t:name,size
		// m:off,name,size,[h:hint,...]
		fmt.Printf("t/%s/%x\n", s.Name, s.Size)
		for _, m := range s.Members {
			fmt.Printf("m/%x/%s/%x", m.Offset, m.Name, m.Size)
			if len(m.Type) > 0 {
				fmt.Printf("/%s", m.Type)
			}
			fmt.Printf("\n")
		}
	}
}
