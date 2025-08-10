#include <iostream>
#include "../lib/ArgHandler.h"
#include "../lib/TrojanLetter.h"

int main(const int argc, char *argv[]) {
    try {
        const auto argHandler = ArgHandler::fromArgs(argc, argv);
        TrojanLetter::runWithArgs(argHandler);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        ArgHandler::printHelp();
        return -1;
    } catch (...) {
        std::cerr << "An unknown error occurred." << std::endl;
        ArgHandler::printHelp();
        return -1;
    }
}
