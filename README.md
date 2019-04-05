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

<i>api_url =

api_key =
 </i>
 
In maltego, in the transforms manager,modify the path of the working directory.

## Usage

The transforms are:
    
    * to check if the observable in Yeti
    * to link the tag of an observable of Yeti
    * to link the datasource of an observable of Yeti 