include_directories( .)
include_directories( ../olc_net)

add_executable(thresh1_a thresh_client_a.cpp )
add_executable(thresh1_b thresh_client_b.cpp)
add_executable(thresh1_server thresh_server.cpp)






