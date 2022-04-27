project('dfuzzer', 'c',
        version : '1.4',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr',
                'warning_level=2',
        ],
)

libgio = dependency('gio-2.0', required : true)
libffi = dependency('libffi', required : true)

subdir('src')

executable(
        'dfuzzer',
        dfuzzer_sources,
        dependencies : [libgio, libffi],
        install : true
)

if get_option('dfuzzer-test-server')
        executable(
                'dfuzzer-test-server',
                dfuzzer_test_server_sources,
                dependencies : [libgio],
                c_args : '-Wno-unused-parameter',
                install : true,
        )
endif

install_data('src/dfuzzer.conf', install_dir : get_option('sysconfdir'))
install_man('man/dfuzzer.1')
