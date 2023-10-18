fn main() {
    cc::Build::new()
	.file("src/oshelpers.c")
	.compile("gensiooshelpers");
}
