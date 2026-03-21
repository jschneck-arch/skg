# 0.2.3 (2014-06-17)

* Add `also` to the option object of the extend method. This should be a 
  function class (or an array of) and can be used for multiple inheritance,
  meant for inheriting classes that are not Nuclei based (like EventEmitter)


# 0.2.2 (2014-01-03)

* Add a new event that will be emitted when extended
* A callback can be set on the Nuclei module that will fire when a class is
  extended. Example: require('nuclei').extended = function(newclass){};


# 0.2.1 (2013-11-23)

* Also export the augment function and instanced event emitter when requiring
  the Nuclei module


# 0.2.0 (2013-11-22)

* Fix bug with the __extended__ method


# 0.1.2 (2013-10-13)

* First release after spinning Nuclei off from alchemymvc.