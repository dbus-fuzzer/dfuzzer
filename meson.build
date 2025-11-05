project('dfuzzer', 'c',
        version : '2.5',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr',
                'warning_level=2',
        ],
)

tests = []

libgio = dependency('gio-2.0', required : true)
libdbus = dependency('dbus-1', required : get_option('dfuzzer-test-server'))
libsystemd = dependency('systemd', required : get_option('dfuzzer-test-server'))
xsltproc = find_program('xsltproc', required: false)
prefixdir = get_option('prefix')
sysconfdir = prefixdir / get_option('sysconfdir')

conf = configuration_data()
conf.set('DFUZZER_VERSION', meson.project_version())
conf.set10('WITH_COVERAGE', get_option('b_coverage'))
conf.set_quoted('SYSCONFDIR', sysconfdir)
conf.set('SYSCONFDIR_RAW', sysconfdir)
conf.set('PREFIXDIR_RAW', prefixdir)

config_h = configure_file(
              output : 'config.h',
              configuration : conf)

fs = import('fs')

add_project_arguments('-include', 'config.h', language : 'c')

subdir('src')
subdir('test')

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

        dfuzzer_xml = configure_file(
                input : 'man/dfuzzer.xml.in',
                output : 'dfuzzer.xml',
                configuration : conf,
        )

        custom_target(
                'dfuzzer.1',
                input : dfuzzer_xml,
                output : 'dfuzzer.1',
                command : xsltproc_cmd,
                install : true,
                install_dir : get_option('mandir') / 'man1',
        )
endif

if get_option('dfuzzer-test-server')
        dbus_datadir = libdbus.get_variable(pkgconfig: 'datadir') / 'dbus-1'
        systemd_unitdir = libsystemd.get_variable(pkgconfig: 'systemdsystemunitdir')

        executable(
                'dfuzzer-test-server',
                dfuzzer_test_server_sources + dfuzzer_util_sources,
                include_directories : include_directories('src/'),
                dependencies : [libgio],
                c_args : '-Wno-unused-parameter',
                install : true,
        )

        dfuzzer_test_server_service = configure_file(
                input : 'test/dfuzzer-test-server.service.in',
                output : 'dfuzzer-test-server.service',
                configuration : conf,
        )

        install_data('test/org.freedesktop.dfuzzerServer.conf',
                     install_dir : dbus_datadir / 'system.d')
        install_data('test/org.freedesktop.dfuzzerServer.service',
                     install_dir : dbus_datadir / 'system-services')
        install_data(dfuzzer_test_server_service,
                     install_dir : systemd_unitdir)
endif

install_data('src/dfuzzer.conf', install_dir : sysconfdir)

foreach tuple : tests
        sources = tuple[0]
        name = fs.stem(sources[0])

        exe = executable(
                name,
                sources + dfuzzer_util_sources,
                include_directories : include_directories('src/'),
                dependencies : [libgio],
        )

        # See: https://docs.gtk.org/glib/testing.html#using-meson
        test(name, exe,
             timeout : 60,
             env : [
                     'G_TEST_SRCDIR=@0@'.format(meson.current_source_dir()),
                     'G_TEST_BUILDDIR=@0@'.format(meson.current_build_dir()),
             ]
        )
endforeach

summary({
        'prefixdir'   : prefixdir,
        'sysconfdir'  : sysconfdir,
})

# vi: sw=8 ts=8 et:
