# Go bindings.  swig generates the raw wrapper into the gensio package
# directory and "go build" compiles it with cgo, like the Makefile.am
# files do.  The go.mod files are written directly instead of running
# "go mod init/edit/tidy".

go_mod_name = 'github.com/cminyard/go/gensio'

go_cxx = meson.get_compiler('cpp')
go_env = environment()
go_env.set('CC', ' '.join(cc.cmd_array()))
go_env.set('CXX', ' '.join(go_cxx.cmd_array()))
go_env.set('CGO_CPPFLAGS', ' '.join([
    '-I' + meson.project_source_root() / 'include',
    '-I' + meson.project_build_root() / 'include',
    '-I' + meson.project_source_root() / 'c++/include',
    '-I' + meson.project_source_root() / 'c++/swig/include',
]))
go_libdirs = [meson.project_build_root() / 'lib',
              meson.project_build_root() / 'c++/lib']
go_ldflags = []
foreach d : go_libdirs
    go_ldflags += ['-L' + d, '-Wl,-rpath,' + d]
endforeach
go_ldflags += ['-lgensiooshcpp', '-lgensiocpp', '-lgensiomdnscpp',
               '-lgensioosh', '-lgensio', '-lgensiomdns']
go_env.set('CGO_LDFLAGS', ' '.join(go_ldflags))

go_mod_in = files('go.mod.in')
# The version replace'd local modules get in go.mod
go_mod_ver = ' v0.0.0-00010101000000-000000000000'

# "go build" has to run in the module's directory
go_sh = find_program('sh')
go_build = [go_sh, '-c', 'cd "$1" && shift && exec "$0" build "$@"',
            golang.full_path()]

go_libs = [libgensiooshcpp, libgensiocpp, libgensiomdnscpp,
           libgensioosh, libgensio, libgensiomdns]

subdir('gensio')
subdir('examples')
subdir('tests')
