#ifndef LOG_H
#include <iostream>
#define LOG_H

#define DEBUG_LVL 2 // > 3 for for loop queue prints

#if DEBUG_LVL == 3
#define  DEBUG(x) do { std::cout << x; } while (0)
#define PRINT(x) do { std::cout << x; } while (0)
#define ERR(x) do { std::cerr << x; } while (0)

#elif DEBUG_LVL == 2
#define  DEBUG(x)
#define PRINT(x) do { std::cout << x; } while (0)
#define ERR(x) do { std::cerr << x; } while (0)

#elif DEBUG_LVL == 1
#define  DEBUG(x)
#define PRINT(x)
#define ERR(x) do { std::cerr << x; } while (0)
#endif

#endif // LOG_H