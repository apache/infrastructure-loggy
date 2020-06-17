# infrastructure-loggy
Loggy Jr. for ASF Infra

To enable, add the following yaml:


~~~yaml
pipservice:
  loggy:
    tag: master
    yamlcfg: "your loggy cfg yaml here"
~~~

Requires `loggy.yaml` to be defined in the yamlcfg variable, either via yaml or eyaml.
