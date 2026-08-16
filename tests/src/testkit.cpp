#include <functional>
#include <iostream>
#include <map>
#include <passl/client.hpp>
#include <passl/server.hpp>

int server(char*[], int)
{
  passl::server server(3333, 1);
  server.start();

  return 0;
}

int client(char*[], int)
{
  passl::client client;
  client.connect("127.0.0.1", 3333);
  return 0;
}

int debugPass(char* argv[], int argc)
{
  std::cout << "Arg pass: ";
  for (int i = 0; i < argc; i++)
  {
    std::cout << argv[i];
  }
  std::cout << std::endl;

  return 0;
}

std::map<std::string, std::function<int(char* argv[], int argc)>> handler = {
  { "--server", &server },
  { "--client", &client }
};

void printUsage(std::string bin_name)
{
  std::cout << " " << std::endl;
  std::cout << "usage: " << bin_name << " [option]" << std::endl;
  std::cout << "Available options: [";
  for (auto v_pair : handler)
  {
    std::cout << "  " << v_pair.first;
  }
  std::cout << "]" << std::endl;
}

int main(int argc, char* argv[])
{
  if ((argc - 1) < 1)
  {
    std::cout << "Invalid usage." << std::endl;
    printUsage("testkit");
    return 1;
  }

  if (handler.count(argv[1]) != 1)
  {
    std::cout << "Invalid option: " << argv[1] << std::endl;
    printUsage("testkit");
    return 1;
  }

  return handler[argv[1]](argv, argc);
}
