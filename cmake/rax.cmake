include(ExternalProject)

ExternalProject_Add(rax
    PREFIX ${WROKDIR}/deps/
    GIT_REPOSITORY https://github.com/antirez/rax.git
    CONFIGURE_COMMAND ""
    BUILD_COMMAND  ""
    INSTALL_COMMAND ""
)   
# .so dir set
# set(rax_LIB       ${WROKDIR}/deps/src/rax-build/librax.so)
# .h dir set
set(rax_DIR   ${WROKDIR}/deps/src/rax)
