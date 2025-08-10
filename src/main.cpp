#include <iostream>
#include "../lib/ArgHandler.h"
#include "../lib/TrojanLetter.h"

int main(const int argc, char *argv[]) {
    try {
        const auto argHandler = tl::ArgHandler::fromArgs(argc, argv);
        tl::TrojanLetter::runWithArgs(argHandler);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        tl::ArgHandler::printHelp();
        return -1;
    } catch (...) {
        std::cerr << "An unknown error occurred." << std::endl;
        tl::ArgHandler::printHelp();
        return -1;
    }
}
