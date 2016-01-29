ATTENTION: THIS IS AN ALPHA DEVELOPMENT RELEASE, MEANING THE PROGRAM DOES NOT
BEHAVES IN THE SAME WAY EXPECTED BY THE END RESULTING IDEA. AS YOU MAY NOTICED
THERE ARE SOME PARTS OF THE CODE IN WHICH ARE COMMENTED OUT, THESE PARTS ARE
THE ONES I'M CURRENTLY WORKING AT! CONTRIBUTIONS ACCEPTED!

# File-Infector
File Infector Injects code into Executables.

Originally started as a proof-of-concept, then I got interested how it looked and decided to implement it using C++
and a PE Manipulation Library.

as shown here: https://www.youtube.com/watch?v=KwYqrVuP56A

# PE Manipulation Library ("PE Bliss")
The library used in this project is "PE Bliss" from Kaimi at: https://code.google.com/archive/p/portable-executable-library/
Author's Website: https://kaimi.ru

# Project Compilation
This project works under the wings of PE Bliss, meaning you will have to compile this library and drop this project folder
inside wherever you created/dropped your PE Bliss project and compiled it.

So the idea generally is this one:
  
    <PE Bliss Library\>
             <<..FileInfectorTest\>>
That way it will compile with the default settings and you don't have to do extra work.

# Usage
The usage of File Infector is really simple as you may see in the code, simply drop a file (which is not .NET)
on the executable and it will generate the code of injecton, the resulting executable will have the injected code
and then you will be able to execute it and see how the execution goes.
