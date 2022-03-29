# MTRACE

## Building

### Pintool

```bash
MTRACE_DIR=pin/source/tools/mtrace
mkdir $MTRACE_DIR
cp mtrace.cpp makefile.rules $MTRACE_DIR
cd $MTRACE_DIR
make
```

### Golang

Download and install Golang.

```
go get github.com/dgryski/go-metro github.com/dgryski/go-minhash github.com/dgryski/go-spooky
go build minhash.go
```

## Usage

### MTRACE

Memory tracing swiss army knife.

```
-b  [default 0]
        trace reads and writes
-c  [default 0]
        count of allocations
-cs [default 0]
        describe the callstack hashes
-e  [default ""]
        callstack type to focus on
-f  [default 0]
        log memory related functions (malloc, mmap, brk, etc.) as they are hit");
-g  [default 0]
        address of lexer::getChar function in libpoppler
-i  [default 0]
        log the basic block head address
-l  [default 0]
        list allocs
-m  [default ""]
        image name to restrict rw tracing to
-ms [default ""]
        sequence to match before enabling rw tracing
-o  [default ]
        specify file name for mtrace output
-t  [default 0]
        alloc histogram based on callstack
-x  [default 0]
        alloc histogram based on callstack and size
-y  [default 0]
        alloc histogram based on size
-n  [default ""]
        inference type definition file
-r  [default ""]
        r/w filter file
```

**`-b`** Logs all memory reads and writes to heap objects. Outputs objects as `callstack_hash,size,rw_pattern` at the end of execution.

**`-c`** Count of calls to malloc.

**`-cs`** This will output the callstack for each used callstack hash as it is encountered. Callstacks are output as multiple lines of `callstack_hash=image_hash@relative_address`. Like `-i`, image hashes will be explained automatically when using this.

**`-e`** This restricts tracing to a single callstack hash.

**`-f`** Traces functions related to memory allocations.

**`-g`** This option will print characters as they are returned from `getChar`. The argument is the address of the `lexer::getChar` function in libpoppler. Accepts decimal or `0x`-prefixed hexadecimal.

**`-i`** Traces the instruction pointer at a basic block level. Format is `image_hash@relative_addr`. Image hashes and their input string are output as they are encoutered.

**`-l`** Lists allocations as the occur. Format is (`size,callstack_hash`). Can be used with **`-cs`** to explain the callstack hashes.

**`-m`** This will restrict read/write tracing (`-b`) to a specific image (e.g. libpoppler). It is a substring search. 

**`-ms`** When used, this sequence will need to be output by getChar returns before memory reads and writes will be stored. Required `-g` and `-b`.

**`-o`** Output file name. Default `stdout`.

**`-t`** Allocation histogram based on callstack hash. Can be used with `-cs` to explain the callstack hashes.

**`-x`** Allocation histogram based on callstack hash and size. Can be used with `-cs` to explain the callstack hashes.

**`-y`** Allocation histogram based allocation size. 

**`-n`** Type definition file. Type file describes types and their members in the following format -
        `t/name/size`
        `m/offset/name/size[/h:type]`

**`-r`** R/W trace filter file. Contains a list of new line separated addresses, in hex, to enable r/w tracing on.

### Minhash

Performs minhash over the **lines** of a file (or stdin). Produces a length 100 uint64 signature.

```
Usage of minhash:
  -i string
        input file (default stdin)
  -n int
        number of minhashes to use (default 10)
  -c value
        signature files to compare (-c s1.json -c s2.json ...)
```

```bash
$ cat trace1 | minhash > s1.json
$ minhash -i trace2 > s2.json
$ minhash -c s1.json -c s2.json
0.65
```

Ideally you will minhash a newline-delimited trace, then index the N (100) hashes it produces in a database. Then for any trace you can find a similar file by first querying for any other signature that shares a single minhash, then performing a full comparison against that signature.