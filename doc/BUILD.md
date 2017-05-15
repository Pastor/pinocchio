1. Before build, in console execute commands:
    ```
    @> git submodule init
    @> git submodule update
    ```
    
2. Generate Visual Studio Solution - `cmake .. -DCMAKE_BUILD_TYPE=Debug -G "Visual Studio 14 2015 Win64"`