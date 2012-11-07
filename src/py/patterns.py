"""
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.

Design Patterns

implements certain oo design patterns for python such as
abstract base classes, singletons and typed data structures.
an interface can be implemented by using abstractbaseclass() as base class
and define abstract methods calling abstract() on call.
to create singleton classes just inherit from class singleton(). All
objects will be of the same instance.
"""
__all__ = ["abstractbaseclass","abstract","implement","singleton","typedlist","typeddict"]

# +-------------------------------------------------------------+
# |-FUNCTIONS---------------------------------------------------|
# +-------------------------------------------------------------+
def abstract ():
	"""abstract() -- raise NotImplementedError"""
	raise NotImplementedError("Abstract method must be overridden")

def implement():
	"""implement() -- raise NotImplementedError"""
	raise NotImplementedError("Method not implemented")

# +-------------------------------------------------------------+
# |-CLASSES-----------------------------------------------------|
# +-------------------------------------------------------------+
class abstractbaseclass (object):
	"""Abstract Base Class
	
	to implement abstract classes and interfaces use (abstractbaseclass) as base class
	and implement interface methods that call the function abstract().
	"""
	def __init__ (self):
		"""__init__() -- raises exception"""
		raise NotImplementedError("Abstract Base Class cannot be instantiated")

	def __repr__ (self):
		"""__repr__ (self) -> return canonical string representation"""
		return "<%s.%s instance at %s>" % \
			(self.__class__.__module__,self.__class__.__name__,hex(id(self)))

	def __str__ (self):
		"""__str__ (self) -> return string representation"""
		return str(self.__dict__)
# +-------------------------------------------------------------+
class singleton (abstractbaseclass):
	"""Singleton design pattern

	checks to see if an __instance_ exists already for this class.
	compare classtypes so that subclasses will create their
	own __instance objects.
	to create singletons just define classes with (singleton)
	as base class. this guarantees that only one instance
	can be generated.
	"""
	__instance_ = None

	def __new__(classtype, *args, **kwargs):
		if classtype != type(classtype.__instance_):
			classtype.__instance_ = object.__new__(classtype, *args, **kwargs)
		return classtype.__instance_
# +-------------------------------------------------------------+
class typedlist (list):
	"""typedlist class
	
	implements a typed list, that is a list that must contain
	elements of a certain type. works exactly as list() with the
	exception that the class of the first item that is inserted 
	is used as the lists type. alternatively, the list type
	can also be passed to the constructor by setting argument t to
	any class (eg int). all additional items must be of the same type.
	"""
	def __init__ (self, l=[], t=None):
		"""__init__ ([]) -- instantiate typedlist object
		
		@t		--		a reference class (eg int)
		@l		--		list to instantiate, is type checked against t
						or l[0] if t==None
		"""	
		if t.__class__ != None.__class__: self.__lclass_ = t
		list.__init__(self,l)
		for item in self: self._check_(item)

	def _check_ (self,item):
		"""_check_(item) -- check type of item
		
		@item	--	item to check the type of
		@raise 	--	TypeError if not isinstance(item,type(self[0]))
		"""
		try:
			if not isinstance(item,self.__lclass_):
				raise TypeError, 'items must be %s not %s' % (self.__lclass_,item.__class__)
		except AttributeError:
			self.__lclass_ = item.__class__
		
	def __str__ (self):
		# list.__str__ -> self.__repr__
		return list.__repr__(self)

	def __repr__ (self):
		if hasattr(self,'__lclass_'):
			return "%s(%s,%s)" % \
				(self.__class__.__name__,list.__repr__(self),self.__lclass_.__name__)
		else:
			return "%s(%s)" % (self.__class__.__name__,list.__repr__(self))
	
	def __setitem__ (self,i,item):
		self._check_(item); list.__setitem__(self,i,item)

	def __add__ (self,other):
		return list.__add__(self,other)

	def __iadd__ (self,other):
		return list.__iadd__(self,other)
	
	def __setslice__ (self,s,l):
		for i in l: self._check_(i)
		list.__setslice__(self,s,l)

	def insert (self,index,item):
		self._check_(item); list.insert(self,index,item)

	def append (self,item):
		self._check_(item); list.append(self,item)

	def extend (self,l):
		for i in l: self._check_(i)
		list.extend(self,l)
# +-------------------------------------------------------------+
class typeddict (dict):
	"""Typed Dictionary class
	
	implements a typed dictionary. keys and values must be
	of a specific type. types can be passed as arguments to
	the constructor. if no types are passed, the types of the
	first { key : value } pair inserted will be used as 
	type definitions.
	"""
	def __init__ (self, d = {}, kc = None, vc = None):
		if kc.__class__ != None.__class__: self.__kclass_ = kc
		if vc.__class__ != None.__class__: self.__vclass_ = vc
		dict.__init__(self,d)
		for k in self.keys(): self._check_(k,self[k])

	def __str__ (self):
		# dict.__str__ -> self.__repr__
		return dict.__repr__(self)
	
	def __repr__ (self):
		return "%s(%s)" % (self.__class__.__name__,dict.__repr__(self))

	def _check_ (self,k,v):
		"""_check_(k,v) -- check type of key:val

		@raise 	--	TypeError if not isinstance(item,type(self[0]))
		"""
		try: self.__kclass_
		except: self.__kclass_ = k.__class__
		try: self.__vclass_
		except: self.__vclass_ = v.__class__
		if not isinstance(k,self.__kclass_) or not isinstance(v,self.__vclass_):
			raise TypeError, 'items must be {%s:%s} not {%s:%s}' % \
				(self.__kclass_,self.__vclass_,k.__class__,v.__class__)
	
	def __setitem__ (self,k,v):
		self._check_(k,v); dict.__setitem__(self,k,v)
	
	def update (self,E={},**F):
		"""D.update(E, **F) -> None."""
		try:
			E.has_key
			for k in E: self._check_(k,E[k])
		except AttributeError:
			for (k,v) in E: self._check_(k,v)
		for k in F: self._check_(k,F[k])
		return dict.update(self,E,**F)
# +-------------------------------------------------------------+
# EOF
