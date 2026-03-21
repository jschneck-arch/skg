# Nuclei
Nuclei provides you with an Object Oriented inheritance system allowing you
to straightforwardly create classes, while maintaining standard prototype
functionality.




## Install

Download the package through npm:

```bash
npm install nuclei
```


## Usage

Require `Nuclei`, the base class from which all others inherit:

```javascript
var Nuclei = require('nuclei').Nuclei;
```



### Class Properties

Every class has a few properties you can use:


#### extend method

In order to create a new class, you need to use the extend method, like this:

```javascript
Nuclei.extend([ClassName], NewClassConstructor, [OptionsObject]);
```

- ClassName: A string containing the name of the class you wish to extend.
Optional, because each class has its own `extend` method.

- NewClassConstructor: A *named* function containing all the methods for this
class. These methods should be assigned to the `this` variable, and should also
be named! This function will be executed immediately and will not be re-executed
upon instancing a new object. So anything in here will be shared by all
instances.

- OptionsObject: An optional object containing special configuration. Mostly
used by internal Nuclei stuff.
  - also: A class (or array of classes) for multiple inheritance. Especially
    useful for non-nuclei classes, like EventEmitter.

---


#### overload method

This is basically the same as extending the class, but it is used to overwrite
the class you're extending.

You can even overload a class that does not exist yet.

```javascript
Nuclei.overload([ClassName], NewClassConstructor);
```

- ClassName: A string containing the name of the class you wish to overload.
Optional. If the class does not exist yet, it will be overloaded once it does.
Warning: Does not affect already existing instances.

- NewClassConstructor: Same as the `extend` method parameter.

---


#### parent property

The parent property of the class is a reference to its parent class.

---


### Class Instance Magic Methods

Every instance has a bit of magic:

- `init`: This is the 'constructor' method. It will receive all the parameters
passed at instancing.

- `__extended__`: This method runs when the class is being extended.
This runs outside of any instance, but it still has access to 'parent()'.

- `augment`: This method creates an 'augmented' version of the current instance.
You can read more about this in the 'augmentation' section.

- `augmented`: This method runs after the instance has been augmented.

- `parent`: The parent method calls a method from the parent class. More can be
read in the 'parent' section.

---


### Create a new class

You can create a basic class by using the `extend` method in this way:

```javascript
var Animal = Nuclei.extend(function Animal() {

	this.init = function init() {
		console.log('Animal has been inited');
	};

	this.speak = function speak() {
		console.log('What does a generic animal say?');
	};
});

var myAnimal = new Animal();
// >>> "Animal has been inited"

myAnimal.speak();
// >>> "What does a generic animal say?"
```

---


### Extend a class

This is basically the same as creating a new class, since creating a new class
is actually extending from the `Nuclei` base class.

```javascript
var Dog = Animal.extend(function Dog() {

	this.init = function init(color) {
		this.color = color;
		console.log('Dog has been inited');
		this.parent();
	};

	this.speak = function speak() {
		console.log('The ' + this.color + ' dog says: woef!');
	};
});

var myDog = new Dog();
// >>> "Dog has been inited"
// >>> "Animal has been inited"

myDog.speak();
// >>> "The brown dog says: woef!"
```

---


### Augmenting an instance

In certain cases it could be wasteful to create a new instance of a class.
Instead you can augment the instance, which basically creates a new context for
the instance and uses that.

```javascript
var myAugmentedDog = myDog.augment({color: 'augmented'});
myAugmentedDog.speak();
// >>> "The augmented dog says: woef!"
```

---


### Parent

You can call a parent method in several ways inside a method:

- `this.parent()` calls the parent of the current method, passing the same
arguments
- `this.parent(name)` calls the `name` method of the parent class, passing the
same arguments
- `this.parent(name, [arg1, arg2])` calls the `name` method of the parent class,
passing the arguments inside the array as parameters
- `this.parent(name, null, arg1, arg2, arg3)` calls the `name` method of the
parent class, passing the extra arguments as parameters


### Prototype

The prototype system can still be used to add methods to already existing
classes. You can also use the `parent` method inside it.

All children classes will also be able to access this new method, even after
instancing.

```javascript
Animal.prototype.newlyAddedMethod = function newlyAddedMethod(){
	console.log('AnimalMethod');
	this.parent();
};
```