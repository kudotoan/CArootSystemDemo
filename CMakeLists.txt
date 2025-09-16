cmake_minimum_required(VERSION 3.16)

project(CARootSystemDemo VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(OpenSSL_INCLUDE_DIR "D:/Program File/OpenSSL-Win64/include")
set(OpenSSL_LIB_DIR "D:/Program File/OpenSSL-Win64/lib/VC/x64/MT")
set(PKCS11_INCLUDE_DIR "D:/Program File/SoftHSM2/include")
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)
include_directories("${OpenSSL_INCLUDE_DIR}")
link_directories("${OpenSSL_LIB_DIR}")
include_directories("${PKCS11_INCLUDE_DIR}")

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(CARootSystemDemo
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        image/resource.qrc
        Model/hsmconfig.h Model/hsmconfig.cpp
        form_login.h form_login.cpp form_login.ui
        Model/certificate.h Model/certificate.cpp
        pindialog.h pindialog.cpp
        certificate_detail_widget.h certificate_detail_widget.cpp certificate_detail_widget.ui
        CustomDialog/dialog.h CustomDialog/dialog.cpp CustomDialog/dialog.ui

    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET CARootSystemDemo APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(CARootSystemDemo SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(CARootSystemDemo
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_link_libraries(CARootSystemDemo PRIVATE Qt${QT_VERSION_MAJOR}::Widgets libssl.lib libcrypto.lib)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.CARootSystemDemo)
endif()
set_target_properties(CARootSystemDemo PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS CARootSystemDemo
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(CARootSystemDemo)
endif()
