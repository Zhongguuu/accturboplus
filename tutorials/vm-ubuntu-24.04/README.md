# Introduction

Known minor issues that anyone who knows how to fix is welcome to
suggest improvements:

+ The desktop icon for the Wireshark application does not seem to
  exist, at least not under the name that worked for Ubuntu 20.04, so
  it shows up as a question mark.


# Creating the VM

+ Below are the steps to create a brand new VM using Vagrant:
  + Install [Vagrant](https://developer.hashicorp.com/vagrant/docs/installation) on your system if it's not already installed.
  + In a shell/terminal window, change to this `vm-ubuntu-24.04`
    directory inside the `tutorials` directory.
  + Run the below command in the terminal.
    
    ```bash
    vagrant up dev
    ```

  - This command will initiate the creation of a development VM.
  - The VM will include P4 software installed built from source code.

+ `vagrant up` is not supported, as there are not currently
  pre-compiled Ubuntu 24.04 packages being created by anyone.

*Note* that creating a development VM can take several hours,
depending upon the speed of your computer and Internet connection.
