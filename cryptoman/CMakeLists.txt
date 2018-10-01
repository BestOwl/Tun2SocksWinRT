add_library(cryptoman
    cryptoman.c
    cryptoman.h
)

find_package(OpenSSL REQUIRED)
target_link_libraries(cryptoman OpenSSL::Crypto)
