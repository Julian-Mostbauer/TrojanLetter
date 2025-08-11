//
// Created by julian on 8/10/25.
//

#ifndef TROJANLETTER_ARGHANDLER_H
#define TROJANLETTER_ARGHANDLER_H
#include <string>
#include <unordered_map>

namespace tl {
    class ArgHandler {
        std::unordered_map<std::string, std::string> options;

        ArgHandler() = default;

        /** Returns the default value for a given option.
         * This method is used to provide a fallback value when an option is not specified.
         * @param option Name of the option for which to retrieve the default value
         * @return The default value as a string, or an empty string if no default is defined. */
        static inline std::string getDefaultValue(const std::string &option) noexcept;

    public:
        /** Creates an ArgHandler instance from command line arguments.
         * @param argc Argument count
         * @param argv Argument vector
         * @throws std::runtime_error if an unknown argument is provided.
         * @return An ArgHandler instance populated with the parsed options. */
        static ArgHandler fromArgs(int argc, char *argv[]);

        /** Checks if a specified option exists.
         * @param option Name of the option to check
         * @return True if the option exists, false otherwise. */
        [[nodiscard]] bool hasOption(const std::string &option) const noexcept;

        /** Retrieves the value of a specified option.
         * @param option Name of the option to retrieve
         * @return Either the value of the option if it exists, or a default value if it does not. */
        std::string getOption(const std::string &option) const noexcept;

        /** Prints all collected options to the given output stream.
         * @param out Output stream to print the options to
         */
        void printCollectedOptions(std::ostream &out) const noexcept;

        /** Prints the help message to the given output.
         * This method provides usage instructions and available options for the application.
         * @param out Output stream to print the help message to
         */
        static void printHelp(std::ostream &out) noexcept;
    };
}

#endif //TROJANLETTER_ARGHANDLER_H
