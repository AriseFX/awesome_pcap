include(ExternalProject)

ExternalProject_Add(cJSON
    PREFIX ${WROKDIR}/deps/
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG v1.7.14
    CMAKE_COMMAND cmake .. -DENABLE_CJSON_UTILS=On -DENABLE_CJSON_TEST=Off -DCMAKE_INSTALL_PREFIX=./usr
)   
# .so dir set
if (UNIX)
    if (APPLE)
        set(CJSON_LIB       ${WROKDIR}/deps/src/cJSON-build/libcjson.dylib)
    else (APPLE)
        set(CJSON_LIB       ${WROKDIR}/deps/src/cJSON-build/libcjson.so)
    endif (APPLE)
endif (UNIX)



# .h dir set
set(CJSON_DIR   ${WROKDIR}/deps/src/cJSON)
