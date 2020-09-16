# Yetigo 

This is a Maltego Yeti integration tool to view (read-only) data from a Yeti instance. 


## Installation and User Guide:
`git clone `

`cd yetigo`

`virtualenv --python python3 venv`

`pip install -r requirements.txt`

`canari create-profile yetigo`

![Alt Text](/doc/Images/createprofile.png?raw=True)

edit your ~/.canari/yetigo.conf to set 

![Alt Text](/doc/Images/yeticonf.png?=raw=True)

<i>api_url =

api_key =
 </i>
 
In maltego, in the transforms manager,modify the path of the working directory.

![Alt Text](/doc/Images/WorkingDir.png)
## Entities
the entities of yeti must be imported in maltego. 

the entities file is yetigo/resources/etc/
![Alt_text](/doc/Images/entities.png)

## Usage

The transforms are:
    
    * to check if the observable in Yeti
    * to link the tag of an observable of Yeti
    * to link the datasource of an observable of Yeti
## Icons Maltego

All icons used for the all entities is here https://github.com/MISP/intelligence-icons

This work is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License.

    Copyright 2016 Bret Jordan - original works with some potential licensed material
    Copyright 2018 Françoise Penninckx - redesign from scratch
