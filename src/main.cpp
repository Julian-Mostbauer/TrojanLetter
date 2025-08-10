#include <iostream>
#include "../lib/ArgHandler.h"
#include "../lib/TrojanLetter.h"


int tryRun(const tl::ArgHandler &argHandler) {
    try {
        tl::TrojanLetter::runWithArgs(argHandler);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        std::cout << "Check -h for help!" << std::endl;
        return -1;
    } catch (...) {
        std::cerr << "An unknown error occurred." << std::endl;
        std::cout << "Check -h for help!" << std::endl;
        return -1;
    }
}

int main(int argc, char *argv[]) {
    try {
        const auto argHandler = tl::ArgHandler::fromArgs(argc, argv);
        return tryRun(argHandler);
    } catch (const std::exception &e) {
        std::cerr << "Failed to parse arguments: " << e.what() << std::endl;
        std::cout << "Check -h for help!" << std::endl;
        return -1;
    } catch (...) {
        std::cerr << "An unknown error occurred while parsing arguments. Check -h for help!" << std::endl;
        return -1;
    }
}
