var events       = require('events'),
    eventEmitter = new events.EventEmitter(),
    Classes      = {},
    NucleiBaseConstructor,
    augmentObject,
    designator,
    Nuclei,
    inject;

/**
 * Tell all the methods inside an object where they come from
 *
 * @author   Jelle De Loecker   <jelle@codedor.be>
 * @since    0.0.1
 * @version  0.0.1
 *
 * @type   {Function}
 *
 * @param    {Object}   object     The object containing the methods (prototype)
 * @param    {String}   ownerName  The name of the owner class
 * @param    {String}   parentName The name of the parent class
 */
designator = function designator(object, ownerName, parentName) {

	var methodName;

	if (typeof object !== 'object') return;

	// Go over every method in the given object
	for (methodName in object) {

		// If the method is a function and doesn't have an owner set yet
		if (typeof object[methodName] === 'function'&& !object[methodName].__ownerClass__) {
			object[methodName].__ownerClass__ = ownerName;
			object[methodName].__parentClass__ = parentName;
		}
	}
};

/**
 * Inject the properties of one or more objects into the target object.
 * The target object is modified in place and also returned.
 *
 * @author   Jelle De Loecker   <jelle@codedor.be>
 * @since    0.0.1
 * @version  0.0.1
 *
 * @param   {Object}   target     The object to inject the extension into
 * @param   {Object}   first      The object to inject
 *
 * @returns {Object}   Returns the injected target
 */
inject = function inject(target, first, second) {
	
	var length = arguments.length,
	    extension,
	    argumentNr,
	    propertyNr;
	
	// Go over every argument, other than the first
	for (argumentNr = 1; argumentNr <= length; argumentNr++) {
		extension = arguments[argumentNr];

		// Go over every property of the current object
		for (propertyNr in extension) {
			target[propertyNr] = extension[propertyNr];
		}
	}
	
	return target;
};

/**
 * Augment certain properties into an instance's context,
 * without modifying the original instance.
 *
 * @author   Jelle De Loecker   <jelle@codedor.be>
 * @since    0.0.1
 * @version  0.0.1
 *
 * @param    {Object}   original   The original instance/context
 * @param    {Object}   addition   The object to inject into it
 *
 * @return   {Object}
 */
augmentObject = function augment(original, addition) {

	var OriginalContextWrapper, augmentedContext;
	
	// Create a new, empty function
	OriginalContextWrapper = function OriginalContextWrapper(){};

	// Set the original context object as its prototype
	OriginalContextWrapper.prototype = original;

	// Now create a new instance of it
	augmentedContext = new OriginalContextWrapper();

	// If a (valid) addition is given, augment it
	if (typeof addition === 'object') {
		// Now inject the additions into the new context,
		// this will leave the original context untouched
		inject(augmentedContext, addition);

		// Also add the additions one level deeper,
		// that way we can retrieve what was augmented
		inject(augmentedContext, {__augment__: addition});

		// If this instance has an augmented() method, run it
		if (typeof augmentedContext.augmented === 'function') {
			augmentedContext.augmented(addition);
		}
	}

	// Finally return the augmentedContext
	return augmentedContext;
};

/**
 * The NucleiBaseConstructor function
 *
 * @author   Jelle De Loecker   <jelle@codedor.be>
 * @since    0.0.1
 * @version  0.0.1
 *
 * @type   {Function}
 */
NucleiBaseConstructor = function NucleiBaseConstructor() {};

/**
 * The function that does the extending
 *
 * @author   Jelle De Loecker   <jelle@codedor.be>
 * @since    0.0.1
 * @version  0.2.3
 *
 * @type   {Function}
 *
 * @param    {Function}   _extension   The extending class
 * @param    {Object}     _options     Extra options
 * @param    {Object}     _three       Depends on overloading...
 *
 * @returns  {Function}   A new class
 */
NucleiBaseConstructor.extend = function extend(_extension, _options, _three, _callback) {

	var origin    = this,        // The originating class
	    options   = _options,
	    callback  = _callback,
	    extension = _extension,  // The new, extending class
	    new_constructor,
	    also,
	    key;
	
	// Function overloading handler
	if (typeof _options !== 'object') {
		if (typeof _three === 'object') {
			options = _three;
			_three = undefined;
		}
		else options = {};
	}
	
	if (typeof _options === 'function') {
		extension = _options;
		_options = undefined;
	}
	
	if (typeof _extension === 'string') {
		origin = Classes[_extension];
	}

	if (typeof extension !== 'function') {
		if (typeof _three === 'function') {
			extension = _three;
		} else {
			// If there is no extension function, the name has to be inside
			// the options object
			eval('extension = function ' + options.name + '() {};');
		}
	}

	// Register new classes by default
	if (typeof options.register === 'undefined') options.register = true;
	
	if (!options.name) {
		options.name = '';
		if (extension.name) {
			options.name = extension.name;
		} else {
			// If the extending function does not have a name, disable registering
			options.register = false;
		}
	}

	// Create a new instance of the class that is being extended
	// Passing the __extending__ option will make sure
	// the init() method is not called
	var _super = new origin({__extending__: true, __overloading__: options.overloading});

	// Create a temporary instance of the extension class
	// Since no extension has happened yet, no NucleiBaseConstructor magic is inside this
	// class. It won't do anything funky.
	var _child = new extension();

	// Set the method ownership
	designator(_child, options.name, origin.name);

	// Save the old parent
	//_super._parent = {_parent: _super._parent};
	
	// Create the first part of the new constructor
	// We apply it later on inside new_constructor, this way we don't have to
	// put everything inside a big string
	var internal_constructor = function internal_constructor() {

		var arg      = arguments[0],
		    passArgs = arguments,
		    i;

		// If this constructor is called because we're creating a temporary
		// class used for extending another class, don't call the parent __ic__
		if (typeof arg === 'object' && arg.__extending__ === true) {

		} else {
			// Do call the parent internal constructor, and tell it we're instancing
			this.parent('__ic__', null, {__instancing__: true});
		}
		
		// Do not execute the init function when creating a temporary object
		if (typeof arg === 'object' && (arg.__extending__ === true || arg.__instancing__ === true)) {
			// The __extending__ option was found, so init() is not called
			// __instancing__ was also found, so don't call any parent init() functions
		} else {

			if (typeof arg === 'object' && arg.__passArgs__) {
				passArgs = arg.__passArgs__;
			}

			if (also && also.length) {
				for (i = 0; i < also.length; i++) {
					also[i].call(this);
				}
			}

			if (typeof this.preInit === 'function') this.preInit.apply(this, passArgs);
			if (typeof this.init === 'function') this.init.apply(this, passArgs);
			if (typeof this.postInit === 'function') this.postInit.apply(this, passArgs);
		}
	};

	// Use eval to create the constructor for our new class,
	// that way we can set the class (function) name (options.name)
	eval('new_constructor = function ' + options.name + '(){\
		if (!(this instanceof ' + options.name + ')) {\
			throw new Error("Constructor called without new operator");\
		}; internal_constructor.apply(this, arguments)}');
	
	// Set the new parent object as the prototype
	new_constructor.prototype = _super;

	new_constructor.prototype.__parentName = origin.name;
	new_constructor.prototype.__parentClass = origin;

	// Check for multiple inheritance
	if (options.also) {

		also = options.also;

		if (!Array.isArray(also)) {
			also = [also];
		}

		for (i = 0; i < also.length; i++) {
			for (key in also[i].prototype) {
				new_constructor.prototype[key] = also[i].prototype[key];
			}
		}
	}

	// Inject the extending object into the prototype
	for (i in _child) new_constructor.prototype[i] = _child[i];

	// Add the internal constructor
	new_constructor.prototype.__ic__ = internal_constructor;

	// Tell all the methods who owns them
	designator(new_constructor.prototype, options.name, this.name);
	
	// Make it inherit all the class methods, too
	for (key in origin) new_constructor[key] = origin[key];
	for (key in extension) new_constructor[key] = extension[key];

	// Make sure the correct function is set as the constructor
	new_constructor.prototype.constructor = extension;
	
	// Set the name in the prototype, so objects will have this set correctly
	// Don't forget: once a function's .name has been set, it can't be changed
	new_constructor.prototype.name = options.name;
	
	// Set the parent class
	new_constructor.parent = origin;
	
	// Register the class if needed
	if (options.register) {
		
		var _doRegister = true;
		
		if (!options.overloading && typeof Classes[options.name] != 'undefined') {
			console.error('You are overloading an object by using the extending function. Use overload instead');
		}
		
		if (_doRegister) Classes[options.name] = new_constructor;
	}
	
	if (typeof origin.prototype.__extended__ === 'function') {
		origin.prototype.__extended__(origin, new_constructor);
	}
	
	// If the extended callback has been set, call it
	if (exports.extended) {
		exports.extended(new_constructor);
	}

	eventEmitter.emit('ClassExtended', new_constructor);
	eventEmitter.emit('ClassExtended-' + options.name);
	
	if (options.overloading) {
		
		if (typeof new_constructor.__overloaded__ == 'function') {
			new_constructor.__overloaded__(origin.name, origin);
		}
		
		eventEmitter.emit('ClassOverloaded-' + options.name);
	}

	return new_constructor;
};

/**
 * Overloading is basically the same as extending a class,
 * but it overwrites the existing class.
 *
 * @author   Jelle De Loecker   <jelle@codedor.be>
 * @since    0.0.1
 * @version  0.0.1
 *
 * @param    {Function}   _overload    The extending class
 * @param    {Object}     _extra       Extra options
 *
 * @returns  {Function}   A new class
 */
NucleiBaseConstructor.overload = function overload(_overload, _extra) {

	var className = this.name,
	    overloader;

	if (typeof _overload === 'string') {
		className = _overload;
		_overload = _extra;
	}

	// The actual function that does the overloading
	overloader = function overloader() {
		var NucleiBaseConstructor = Classes[className];
		NucleiBaseConstructor.extend(_overload, {overloading: true});
	}
	
	if (typeof Classes[className] !== 'undefined') {
		overloader();
	} else {
		
		// If the class does not exist yet, wait 'till it does
		eventEmitter.once('ClassExtended-' + className, function() {
			overloader();
		});
	}
};

/**
 * Create the actual Nuclei class
 *
 * @author   Jelle De Loecker   <jelle@codedor.be>
 * @since    0.0.1
 * @version  0.0.1
 *
 * @type   {Function}
 */
Nuclei = NucleiBaseConstructor.extend(function Nuclei() {


	/**
	 * Function that runs when this class is being extended
	 *
	 * @author   Jelle De Loecker   <jelle@codedor.be>
	 * @since    0.0.1
	 * @version  0.0.1
	 *
	 * @type   {Function}
	 *
	 * @param  {String}    parentClassName
	 */
	this.__extended__ = function __extended__(parentClassName) {};

	/**
	 * Function that runs when this class is instanced,
	 * before this.init()
	 *
	 * @author   Jelle De Loecker   <jelle@codedor.be>
	 * @since    0.1.1
	 * @version  0.1.1
	 *
	 * @type   {Function}
	 */
	this.preInit = function preInit() {};
	
	/**
	 * Function that runs when this class is instanced
	 *
	 * @author   Jelle De Loecker   <jelle@codedor.be>
	 * @since    0.0.1
	 * @version  0.0.1
	 *
	 * @type   {Function}
	 */
	this.init = function init() {};

	/**
	 * Function that runs when this class is instanced,
	 * after this.init()
	 *
	 * @author   Jelle De Loecker   <jelle@codedor.be>
	 * @since    0.1.1
	 * @version  0.1.1
	 *
	 * @type   {Function}
	 */
	this.postInit = function postInit() {};

	/**
	 * Function that runs when an instance of this class has been augmented
	 *
	 * @author   Jelle De Loecker   <jelle@codedor.be>
	 * @since    0.0.1
	 * @version  0.0.1
	 *
	 * @type   {Function}
	 *
	 * @param  {Object}   addition
	 */
	this.augmented = function augmented(addition) {};

	/**
	 * Augment the current instance of this class
	 *
	 * @author   Jelle De Loecker   <jelle@codedor.be>
	 * @since    0.0.1
	 * @version  0.0.1
	 *
	 * @type   {Function}
	 *
	 * @param  {Object}   addition
	 *
	 * @return {Object}
	 */
	this.augment = function augment(addition) {
		return augmentObject(this, addition);
	};

	/**
	 * Execute a method function from the parent
	 *
	 * @author   Jelle De Loecker   <jelle@codedor.be>
	 * @since    0.0.1
	 * @version  0.0.1
	 *
	 * @type   {Function}
	 *
	 * @param    {String}   functionname         The name of the wanted property
	 * @param    {Boolean}  useCallingArguments  If true, the arguments from the
	 *                                           calling function will be applied
	 *                                           If an array, these will be applied
	 * @param    {Array}    extraArguments       All other arguments will be applied
	 */
	this.parent = function parent(functionName, useCallingArguments) {
		
		var caller = arguments.callee.caller,
		    searchClass,
		    foundMethod,
		    possibleTarget,
		    parent,
		    args;

		if (typeof useCallingArguments === 'undefined') useCallingArguments = true;
		if (typeof functionName !== 'string') functionName = caller.name;
		
		// If there is no valid functionName, do nothing
		if (!functionName) return;

		// If no parent class is set on the method, it could have been added
		// later through the prototype.
		if (!caller.__parentClass__) {

			// Begin looking for the method in the current class
			searchClass = Classes[this.name];

			// Do this while there is a current class, we'll look through
			// every parent if needed
			while (searchClass) {

				// If the current class has the method inside its prototype,
				// it belongs here
				if (searchClass.prototype.hasOwnProperty(functionName)) {
					foundMethod = searchClass.prototype[functionName];
					break;
				} else {
					// If not, use the parent class as the current class
					searchClass = searchClass.parent;
				}
			}

			// If we've found the method add the appropriate properties,
			// so we won't have to do this again
			if (foundMethod) {
				foundMethod.__ownerClass__ = searchClass.name;
				foundMethod.__parentClass__ = searchClass.parent.name;
			} else {
				return;
			}
		}
		
		// Where to find the parent function or property
		parent = Classes[caller.__parentClass__];

		// If no parent is found, do nothing
		if (!parent) return;

		possibleTarget = parent[functionName];
		
		if (typeof possibleTarget === 'undefined') {
			possibleTarget = parent.prototype[functionName];
		}
		
		if (typeof possibleTarget === 'function') {
			
			// Use the arguments from the function that called us
			if (useCallingArguments === true) {
				args = arguments.callee.caller.arguments;
			} else if (useCallingArguments && (useCallingArguments instanceof Array || typeof useCallingArguments.length != 'undefined')) {
				// If it's an array, use those as arguments
				args = useCallingArguments;
			} else {
				// Turn the array-like arguments object into a real array
				args = Array.prototype.slice.call(arguments);
				
				// Remove the function name
				args.shift();
				
				// Remove the useCallingArguments
				args.shift();
			}
			
			// Execute the parent function with the appropriate arguments
			return possibleTarget.apply(this, args);
		} else if (typeof possibleTarget !== 'undefined') {
			return possibleTarget;
		} else {
			console.warn('Could not find parent property ' + functionName + ' from ' + caller.__ownerClass__ + ' looking in ' + caller.__parentClass__ + ' (Request context: ' + this.name + ')');
		}
	};

});

// Export the Nuclei class
exports.Nuclei = Nuclei;

// Export the collection of classes
exports.Classes = Classes;

// Export the inject function
exports.inject = inject;

// Export the augment function
exports.augment = augmentObject;

// Export the event emitter
exports.events = eventEmitter;

// Export the extended callback property
exports.extended = false;