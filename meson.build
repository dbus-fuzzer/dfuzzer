project('dfuzzer', 'c',
        version : '2.0',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr',
                'warning_level=2',
        ],
)

libgio = dependency('gio-2.0', required : true)
xsltproc = find_program('xsltproc', required: false)

conf = configuration_data()
conf.set('DFUZZER_VERSION', meson.project_version())
conf.set10('WITH_COVERAGE', get_option('b_coverage'))

config_h = configure_file(
              output : 'config.h',
              configuration : conf)

add_project_arguments('-include', 'config.h', language : 'c')

subdir('src')

executable(
        'dfuzzer',
        dfuzzer_sources,
        dependencies : [libgio],
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
                input : 'man/dfuzzer.xml',
                output : 'dfuzzer.1',
                command : xsltproc_cmd,
                install : true,
                install_dir : get_option('mandir') / 'man1',
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
