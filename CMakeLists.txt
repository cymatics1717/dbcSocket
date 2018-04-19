cmake_minimum_required(VERSION 2.8.12)

project(dbcSocket)
set (CMAKE_PREFIX_PATH "/opt/Qt5.10.1/5.10.1/gcc_64/lib/cmake")

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt5Core)
find_package(Qt5Network)


include_directories(dbc)

set(SOURCES
    dbc/dbc_classes.cpp
    dbc/dbchandler.cpp
    dbc/utility.cpp
    main.cpp)

set(HEADERS
    dbc/dbc_classes.h
    dbc/dbchandler.h
    dbc/utility.h)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} Qt5::Core Qt5::Network)
