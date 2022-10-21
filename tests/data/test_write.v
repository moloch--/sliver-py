import os

[callconv: stdcall]
[export: Main]
fn output() {
	mut output := os.open_file("test_write.txt", "w") or {return}
	output.write_string("Hello, DLL!") or {return}
	output.close()
}

fn main () {
	output()
}
