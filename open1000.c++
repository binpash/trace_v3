#include <string.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h> 
#include <stdio.h> 
#include <sys/stat.h> 

using namespace std;
int main(){
    for (int i = 0; i < 1000; i++){
        std::string complete_path = "temp/" + std::to_string(i);
        //cout << complete_path << endl;
        int fd = open(complete_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

        if (fd == -1) {
            perror("Error opening file");
            std::cout << i << std::endl;
            return 1;
            
        }
    }
}