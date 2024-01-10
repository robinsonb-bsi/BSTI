<div align="center">
  <h1 align="center">
    <img src="https://github.com/fancyc-bsi/BSTI/blob/main/assets/bsti.png?raw=true" width="100" />
    <br>
  </h1>
</div>
Bulletproof Solutions Testing Interface
</h1>

<p align="center">
<img src="https://img.shields.io/badge/Python-3776AB.svg?style&logo=Python&logoColor=white" alt="Python" />
</p>
</div>

---

## 📒 Table of Contents
- [📒 Table of Contents](#-table-of-contents)
- [📍 Overview](#-overview)
  - [Features](#features)
- [🚀 Getting Started](#-getting-started)
  - [✔️ Prerequisites](#️-prerequisites)
    - [Windows](#windows)
    - [MacOS](#macos)
    - [Debian based OS](#debian-based-os)
  - [💻 Installation](#-installation)
- [🎮 Using BSTI](#-using-bsti)
  - [Connecting](#connecting)
  - [Home Tab](#home-tab)
  - [Module Editor](#module-editor)
  - [File Transfer](#file-transfer)
  - [View Logs](#view-logs)
  - [Modules](#modules)
    - [JSON Format](#json-format)
    - [Argument Metadata Comments](#argument-metadata-comments)
    - [File Upload Metadata Comments](#file-upload-metadata-comments)
- [Contributing to BSTI](#contributing-to-bsti)

---


## 📍 Overview

### Features


---


## 🚀 Getting Started

### ✔️ Prerequisites

Python3 installed.

To take screenshots, wkhtmltopdf is required:

#### Windows

* https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox-0.12.6-1.msvc2015-win64.exe

#### MacOS

* https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-2/wkhtmltox-0.12.6-2.macos-cocoa.pkg

#### Debian based OS

```bash 
sudo apt update && sudo apt install wkhtmltopdf -y
```

### 💻 Installation
``` bash
Install the required Python packages:

pip install -r requirements.txt

```
---
## 🎮 Using BSTI

```bash

python bsti.py
```
### Connecting
To connect to a BSTG, click "Config" in the top-left corner, then "Configure new BSTG" and enter the login details.  
If you've already connected to that BSTG with BSTI before, it'll show up in the bottom left corner. You can change this on the fly by clicking in that space and selecting another BSTG from the dropdown menu.

### Home Tab

Currently this page just has a link to plextrac, and a dynamic link to the Nessus page for the BSTG you are connected to. More will eventually be here though.

### Module Editor

This page displays the code for the module that is currently selected. If you would like to edit a module you can do so here directly. Just make sure you click **Save Module** before executing the module.  

To select another module click on the box next to "Choose a module to run:" and it will open a dropdown menu of available modules. To execute, simply click "Execute Module" in the bottom right corner, enter any arguments (If necessary), and click "Submit".  

### File Transfer

Pretty straightforward. This tab handles transfering files to and from the BSTG via SCP. The remote path on the BSTG has be entered with the absolute path, but 

### View Logs

This tab will automatically populate with the output from every module that is run. Here are the following options:
- Clicking "Take Screenshot" will generate a screenshot of the entire log. You can crop this afterwards to fit your needs.
- Delete Logs
- Refresh Logs

---

### Modules
To create a new module click Modules -> Create New. This will create a new file in the Modules directory and automatically populate a template to use in the Module Editor tab.

Currently BSTI supports modules written in bash, python, and json. Bash and Python scripts handle actions that can be performed in a single tab, while the JSON format has been setup to allow a single module to perform multiple actions in different tabs.

#### JSON Format

The format for the JSON file should be the following:

```json
{
    "grouped": true,
    "tabs": [
        {
            "name": "Responder",
            "command": "echo 'test'"
        },
        {
            "name": "Echo 1",
            "command": "echo 'Tab 1' && sleep 3600"
        },
        {
            "name": "Echo 2",
            "command": "echo 'Tab 2' && sleep 3600"
        }
    ]
}

```

#### Argument Metadata Comments

BSTI has been built with a specific syntax to handle command line arguments that are needed for a module. These are specified in the comment blocks at the top of each module. 

As an example, here is a sample of one module that is meant to search for NSE scripts, Searchsploit, and Metasploit based on the the arguments provided:

```
#!/bin/bash
# ARGS
# NSE "NSE_Query_String" 
# searchsploit "Query_String"
# MSF "MSF_Search_String"
# ENDARGS
```
The metadata section is denoted by the `ARGS` and `ENDARGS` comments. These are read in the order that they appear, so `NSE_QUERY_STRING` would be the first argument ($1), then searchsploit ($2), etc...

#### File Upload Metadata Comments

BSTI also has an option to include file upload as part of the modules execution flow. The way this works is that it will ask for the path to a local file and upload that to the bstg to the path thats specified in the metadata.

```
#!/bin/bash
# STARTFILES
# targets.txt "Targets_description"
# ENDFILES
# ARGS
# ARG_NAME "arg_description"
# ENDARGS
# AUTHOR:
```
This is useful for instance if you want to create a module that uses nmap, and you want to specify a file for the targets. This way you don't have to go through a seperate process of creating the target file on the bstg and remembering the remote path. You can just create the file locally and upload it when you execute the module.

The files that are uploaded are automatically stored in the /tmp/ directory.

## Contributing to BSTI

Interested in contributing to this project?

Check out the dev guide [here](https://github.com/fancyc-bsi/BSTI/blob/main/DEVGUIDE.md).
