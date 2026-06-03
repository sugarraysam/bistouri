/*
 * hello_go.go — E2E fixture for symbolizer Go support testing.
 *
 * Multi-frame call chain with known symbols. Compiled with:
 *   CGO_ENABLED=0 go build -gcflags='-l' \
 *     -ldflags='-linkmode internal -compressdwarf=false -buildid=' \
 *     -o hello_go hello_go.go
 *
 * Then inject a GNU build ID:
 *   objcopy --add-gnu-debuglink=... is not needed; we use
 *   ld's --build-id directly via external linkmode when available,
 *   or add-section post-hoc.
 *
 * Functions avoid inlining (-gcflags='-l') to guarantee distinct
 * frames for symbolizer testing.
 */

package main

//go:noinline
func targetGoFunction() int {
	x := 42
	return x
}

//go:noinline
func outerGoCall() int {
	return targetGoFunction()
}

func main() {
	_ = outerGoCall()
}
