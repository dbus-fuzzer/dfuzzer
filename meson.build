project('dfuzzer', 'c',
        version : '1.4',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr',
                'warning_level=2',
        ],
)

libgio = dependency('gio-2.0', required : true)
json_glib = dependency('json-glib-1.0', required : true)
xsltproc = find_program('xsltproc', required: false)

subdir('src')

executable(
        'dfuzzer',
        dfuzzer_sources,
        dependencies : [libgio, json_glib],
        install : true
)

if xsltproc.found()
        xsltproc_cmd = [
                xsltproc,
                '--nonet',
                '--xinclude',
                '--output', '@OUTPUT@',
                'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl',
                '@INPUT@',
        ]

        custom_target(
                'dfuzzer.1',
                input: 'man/dfuzzer.xml',
                output: 'dfuzzer.1',
                command: xsltproc_cmd,
                install: true,
                install_dir: get_option('mandir') / 'man1',
        )
endif

if get_option('dfuzzer-test-server')
        executable(
                'dfuzzer-test-server',
                dfuzzer_test_server_sources,
                dependencies : [libgio],
                c_args : '-Wno-unused-parameter',
                install : true,
        )
        install_data('src/org.freedesktop.dfuzzerServer.conf',
                     install_dir : '/etc/dbus-1/system.d')
        install_data('src/org.freedesktop.dfuzzerServer.service',
                     install_dir : '/usr/share/dbus-1/system-services')
        install_data('src/dfuzzer-test-server.service',
                     install_dir : '/usr/lib/systemd/system')
endif

install_data('src/dfuzzer.conf', install_dir : get_option('sysconfdir'))
