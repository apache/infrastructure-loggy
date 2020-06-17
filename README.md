# infrastructure-loggy
Loggy Jr. for ASF Infra

To enable, add the following yaml:


~~~yaml
pipservice:
  loggy:
    tag: master
~~~
There is a sample YAML file in this repo. If you are checking out loggy locally, rename this file to `loggy.yaml` and edit accordingly.


As loggy's configuration may contain secrets, you may be required to define this in EYAML.

To do so, make use of pipservice's `custom_yaml_content` feature, like so:

~~~yaml
pipservice::loggy::custom_yaml_content: DEC::GPG[yaml contents go here]
~~~
This will place a new loggy.yaml inside the `/opt/loggy` directory, with the eyaml contents you just defined here.
