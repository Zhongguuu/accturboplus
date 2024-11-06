# Creating the VM

This directory is here only for historical reference.  The scripts
here _might_ still be useful for creating a VM image based on Ubuntu
20.04 Linux, but they are not regularly tested by anyone, so might not
produce a working system.

See the `vm-ubuntu-24.04` [directory](../vm-ubuntu-24.04) for similar
scripts that can be used to create a VM image based on Ubuntu 24.04
Linux.


+ Below are the steps to create a brand new VM using Vagrant:
  + Install [Vagrant](https://developer.hashicorp.com/vagrant/docs/installation) on your system if it's not already installed.
  + In a shell/terminal window, change to this `vm-ubuntu-20.04`
    directory inside the `tutorials` directory.
  + Run the below command in the terminal.
    
    ```bash
    vagrant up
    ```

  - This command will initiate the creation of a release VM.
  - The VM will include P4 software installed from pre-compiled packages.
  - You can update these packages using `apt upgrade` within the VM.

+ Alternatively, a development VM can be created by running 
  ```bash
  vagrant up dev
  ```

*Note* that creating a development VM can take several hours,
depending upon the speed of your computer and Internet connection.
