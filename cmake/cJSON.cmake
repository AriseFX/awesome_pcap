include(ExternalProject)

ExternalProject_Add(cJSON
    PREFIX ${WROKDIR}/deps/
    GIT_REPOSITORY https://gitee.com/Wyarise/cJSON.git
    GIT_TAG v1.7.14
    CMAKE_COMMAND cmake .. -DENABLE_CJSON_UTILS=On -DENABLE_CJSON_TEST=Off -DCMAKE_INSTALL_PREFIX=/usr
)   
# .so dir set
set(CJSON_LIB       ${WROKDIR}/deps/src/cJSON-build/libcjson.so)
# .h dir set
set(CJSON_DIR   ${WROKDIR}/deps/src/cJSON)
