#include <string.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h> 
#include <stdio.h> 
#include <sys/stat.h> 
#include <thread>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

void open1000files(int id) {
    for (int i = 0; i < 1; i++){
        
        std::string complete_path = "temp/" + std::to_string(id*10000+ i);
        //cout << complete_path << endl;
        int fd = open(complete_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

        if (fd == -1) {
            perror("Error opening file");
            std::cout << i << std::endl;
            return;
            
        }
    }
}

int main(){
    const fs::path dir{"temp"};

    try {
        // Remove the directory and all contents if it exists
        if (fs::exists(dir)) {
            fs::remove_all(dir);
            std::cout << "Removed existing directory: " << dir << "\n";
        }

        // Create a fresh empty directory
        fs::create_directory(dir);
        std::cout << "Created new directory: " << dir << "\n";
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << "\n";
    }
    std::vector<std::thread> threads;
    
    threads.reserve(10);
    std::filesystem::path dir_path = "temp";
    for(int i = 0; i < 4; i++){
        std::thread t(open1000files, i+1);
        threads.push_back(std::move(t));
    }

    for(int i = 0; i < threads.size(); i++){
        threads[i].join();
    }
    return 0;
}
