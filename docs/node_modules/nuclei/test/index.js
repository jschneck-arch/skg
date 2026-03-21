var Nuclei = require('../lib/nuclei.js').Nuclei;

console.log('\nCreating Animal class');
var Animal = Nuclei.extend(function Animal() {

	this.preInit = function preInit() {
		console.log('This is animal\'s preInit method');
	};

	this.init = function init() {
		console.log('Animal has been inited');
	};

	this.speak = function speak() {
		console.log('What does a generic animal say?');
	};

});

console.log('\nCreating Dog class');
var Dog = Animal.extend(function Dog() {

	this.init = function init(color) {
		this.color = color;
		console.log('Dog has been inited');
		this.parent();
	};

	this.__extended__ = function __extended__() {
		console.log('Running extended in ' + this.name);
	}

	this.speak = function speak() {
		console.log('The ' + this.color + ' dog says: woef!');
	};
});

console.log('\nCreating Poodle class');
var Poodle = Dog.extend(function Poodle() {

	this.init = function init() {
		console.log('Poodle has been inited');
		this.parent();
	};

	this.speak = function speak() {
		console.log('Poodle says: poodle');
	};

});

console.log('\nCreating Animal instance');
var a = new Animal;

console.log('\nCreating Dog instance');
var d = new Dog('brown');
var b = new Dog('yellow');
d.speak();
b.speak();

var c = b.augment({color: 'augmented'});
c.speak();

console.log('\nCreating Poodle instance');
var p = new Poodle;

p.speak();

console.log('\n');

p.init()

Animal.prototype.newlyAddedMethod = function newlyAddedMethod(){console.log('AnimalMethod');this.parent();};

console.log('\n');
console.log(Poodle.extend)
console.log(p.constructor);

console.log('\nAn existing method in Poodle:')
console.log(p.init);

console.log('\nThe newly added method to Animal inside Poodle:')
console.log(p.newlyAddedMethod);
console.log('\n');

p.newlyAddedMethod();
Poodle.prototype.newlyAddedMethod = function newlyAddedMethod(){console.log('PoodleMethod');this.parent()};

var Testclass = Nuclei.extend(function Testclass() {

	this.init = function init(message) {
		this.message = message;
	};

	this.tell = function tell() {
		console.log('The message is: ' + this.message);
	};
});

var newTest = new Testclass('instance message');
newTest.tell();


var augmentTest = newTest.augment({message: 'that this is an augment test'});
augmentTest.tell();
