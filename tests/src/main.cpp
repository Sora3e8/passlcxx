#include <iostream>
#include <passl/server.hpp>

int main(int argc, char* argv[])
{
  
  std::cout << "Hello test!" << std::endl;
  passl::server server(3333,1);
  server.start();
  return 0;  
}
