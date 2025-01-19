import unittest
from unittest.mock import patch
import builtins
import itertools
import rlcompleter
from types import MappingProxyType
from test.support import MISSING_C_DOCSTRINGS

class CompleteMe:
    """ Trivial class used in testing rlcompleter.Completer. """
    spam = 1
    _ham = 2


class TestRlcompleter(unittest.TestCase):
    def setUp(self):
        self.stdcompleter = rlcompleter.Completer()
        self.completer = rlcompleter.Completer(dict(spam=int,
                                                    egg=str,
                                                    CompleteMe=CompleteMe))

        # forces stdcompleter to bind builtins namespace
        self.stdcompleter.complete('', 0)

    def test_namespace(self):
        class A(dict):
            pass
        class B(list):
            pass

        self.assertTrue(self.stdcompleter.use_main_ns)
        self.assertFalse(self.completer.use_main_ns)
        self.assertFalse(rlcompleter.Completer(A()).use_main_ns)
        self.assertRaises(TypeError, rlcompleter.Completer, B((1,)))

    def test_global_matches(self):
        # test with builtins namespace
        self.assertEqual(sorted(self.stdcompleter.global_matches('di')),
                         [x+'(' for x in dir(builtins) if x.startswith('di')])
        self.assertEqual(sorted(self.stdcompleter.global_matches('st')),
                         [x+'(' for x in dir(builtins) if x.startswith('st')])
        self.assertEqual(self.stdcompleter.global_matches('akaksajadhak'), [])

        # test with a customized namespace
        self.assertEqual(self.completer.global_matches('CompleteM'),
                ['CompleteMe(' if MISSING_C_DOCSTRINGS else 'CompleteMe()'])
        self.assertEqual(self.completer.global_matches('eg'),
                         ['egg('])
        # XXX: see issue5256
        self.assertEqual(self.completer.global_matches('CompleteM'),
                ['CompleteMe(' if MISSING_C_DOCSTRINGS else 'CompleteMe()'])

    def test_attr_matches(self):
        # test with builtins namespace
        self.assertEqual(self.stdcompleter.attr_matches('str.s'),
                         ['str.{}('.format(x) for x in dir(str)
                          if x.startswith('s')])
        self.assertEqual(self.stdcompleter.attr_matches('tuple.foospamegg'), [])
        expected = sorted({'None.%s%s' % (x,
                                          '()' if x in ('__init_subclass__', '__class__')
                                          else '' if x == '__doc__'
                                          else '(')
                           for x in dir(None)})
        self.assertEqual(self.stdcompleter.attr_matches('None.'), expected)
        self.assertEqual(self.stdcompleter.attr_matches('None._'), expected)
        self.assertEqual(self.stdcompleter.attr_matches('None.__'), expected)

        # test with a customized namespace
        self.assertEqual(self.completer.attr_matches('CompleteMe.sp'),
                         ['CompleteMe.spam'])
        self.assertEqual(self.completer.attr_matches('Completeme.egg'), [])
        self.assertEqual(self.completer.attr_matches('CompleteMe.'),
                         ['CompleteMe.mro()', 'CompleteMe.spam'])
        self.assertEqual(self.completer.attr_matches('CompleteMe._'),
                         ['CompleteMe._ham'])
        matches = self.completer.attr_matches('CompleteMe.__')
        for x in matches:
            self.assertTrue(x.startswith('CompleteMe.__'), x)
        self.assertIn('CompleteMe.__name__', matches)
        self.assertIn('CompleteMe.__new__(', matches)

        with patch.object(CompleteMe, "me", CompleteMe, create=True):
            self.assertEqual(self.completer.attr_matches('CompleteMe.me.me.sp'),
                             ['CompleteMe.me.me.spam'])
            self.assertEqual(self.completer.attr_matches('egg.s'),
                             ['egg.{}('.format(x) for x in dir(str)
                              if x.startswith('s')])

    def test_excessive_getattr(self):
        """Ensure getattr() is invoked no more than once per attribute"""

        # note the special case for @property methods below; that is why
        # we use __dir__ and __getattr__ in class Foo to create a "magic"
        # class attribute 'bar'. This forces `getattr` to call __getattr__
        # (which is doesn't necessarily do).
        class Foo:
            calls = 0
            bar = ''
            def __getattribute__(self, name):
                if name == 'bar':
                    self.calls += 1
                    return None
                return super().__getattribute__(name)

        f = Foo()
        completer = rlcompleter.Completer(dict(f=f))
        self.assertEqual(completer.complete('f.b', 0), 'f.bar')
        self.assertEqual(f.calls, 1)

    def test_property_method_not_called(self):
        class Foo:
            _bar = 0
            property_called = False

            @property
            def bar(self):
                self.property_called = True
                return self._bar

        f = Foo()
        completer = rlcompleter.Completer(dict(f=f))
        self.assertEqual(completer.complete('f.b', 0), 'f.bar')
        self.assertFalse(f.property_called)


    def test_uncreated_attr(self):
        # Attributes like properties and slots should be completed even when
        # they haven't been created on an instance
        class Foo:
            __slots__ = ("bar",)
        completer = rlcompleter.Completer(dict(f=Foo()))
        self.assertEqual(completer.complete('f.', 0), 'f.bar')

    @unittest.mock.patch('rlcompleter._readline_available', False)
    def test_complete(self):
        completer = rlcompleter.Completer()
        self.assertEqual(completer.complete('', 0), '\t')
        self.assertEqual(completer.complete('a', 0), 'and ')
        self.assertEqual(completer.complete('a', 1), 'as ')
        self.assertEqual(completer.complete('as', 2), 'assert ')
        self.assertEqual(completer.complete('an', 0), 'and ')
        self.assertEqual(completer.complete('pa', 0), 'pass')
        self.assertEqual(completer.complete('Fa', 0), 'False')
        self.assertEqual(completer.complete('el', 0), 'elif ')
        self.assertEqual(completer.complete('el', 1), 'else')
        self.assertEqual(completer.complete('tr', 0), 'try:')
        self.assertEqual(completer.complete('_', 0), '_')
        self.assertEqual(completer.complete('match', 0), 'match ')
        self.assertEqual(completer.complete('case', 0), 'case ')

    def test_duplicate_globals(self):
        namespace = {
            'False': None,  # Keyword vs builtin vs namespace
            'assert': None,  # Keyword vs namespace
            'try': lambda: None,  # Keyword vs callable
            'memoryview': None,  # Callable builtin vs non-callable
            'Ellipsis': lambda: None,  # Non-callable builtin vs callable
        }
        completer = rlcompleter.Completer(namespace)
        self.assertEqual(completer.complete('False', 0), 'False')
        self.assertIsNone(completer.complete('False', 1))  # No duplicates
        # Space or colon added due to being a reserved keyword
        self.assertEqual(completer.complete('assert', 0), 'assert ')
        self.assertIsNone(completer.complete('assert', 1))
        self.assertEqual(completer.complete('try', 0), 'try:')
        self.assertIsNone(completer.complete('try', 1))
        # No opening bracket "(" because we overrode the built-in class
        self.assertEqual(completer.complete('memoryview', 0), 'memoryview')
        self.assertIsNone(completer.complete('memoryview', 1))
        self.assertEqual(completer.complete('Ellipsis', 0), 'Ellipsis()')
        self.assertIsNone(completer.complete('Ellipsis', 1))


class TestFilterInterface(unittest.TestCase):

    def test_default_priority(self):
        f = rlcompleter.Filter()
        self.assertEqual(f.priority, 500)

    def test_default_namespace_filter(self):
        f = rlcompleter.NamespaceFilter()
        self.assertTrue(f.filter({}, "", None, ""))

    def test_default_attribute_filter(self):
        f = rlcompleter.AttributeFilter()
        self.assertTrue(f.filter(object(), "", None, ""))


@unittest.mock.patch('rlcompleter._readline_available', False)
class BaseTestFilter:

    filter_class: type[rlcompleter.Filter] = None

    def get_completer(self, namespace=MappingProxyType({})):
        return rlcompleter.Completer(namespace)

    def new_filter(self, priority=None):
        return self.filter_class(priority)

    def add_filter(self, c, f):
        raise NotImplementedError

    def remove_filter(self, c, f):
        raise NotImplementedError

    def assert_filters_equal(self, c, fs):
        raise NotImplementedError

    def test_add_filter(self):
        c = self.get_completer()
        f = self.new_filter()
        self.assertTrue(self.add_filter(c, f))
        self.assert_filters_equal(c, [f])

    def test_add_filters(self):
        c = self.get_completer()

        f1 = self.new_filter()
        r1 = self.add_filter(c, f1)
        self.assertTrue(r1, "first filter is already present")

        f2 = self.new_filter()
        r2 = self.add_filter(c, f2)
        self.assertTrue(r2, "second filter is already present")

        self.assert_filters_equal(c, [f1, f2])

    def test_add_filters_with_priority(self):
        c = self.get_completer()
        self.add_filter(c, f0 := self.new_filter())
        self.add_filter(c, f1 := self.new_filter(priority=20))
        self.add_filter(c, f2 := self.new_filter(priority=10))
        self.add_filter(c, f3 := self.new_filter(priority=10))
        self.add_filter(c, f4 := self.new_filter())
        self.assert_filters_equal(c, [f2, f3, f1, f0, f4])

    def test_add_filters_no_duplicate(self):
        c = self.get_completer()
        f = self.new_filter()

        r1 = self.add_filter(c, f)
        self.assertTrue(r1, "first filter is missing")

        r2 = self.add_filter(c, f)
        self.assertFalse(r2, "not a duplicated filter")

        self.assert_filters_equal(c, [f])

    def test_remove_filter(self):
        c = self.get_completer()
        f = self.new_filter()
        self.assertTrue(self.add_filter(c, f))
        self.assertTrue(self.remove_filter(c, f))
        self.assert_filters_equal(c, [])

    def test_remove_missing_filter(self):
        c = self.get_completer()
        f = self.new_filter()
        self.assertFalse(self.remove_filter(c, f))
        self.assert_filters_equal(c, [])

    def test_default_filter(self):
        raise NotImplementedError

    def test_simple_filter(self):
        raise NotImplementedError

    def test_chain_filters(self):
        raise NotImplementedError


class TestNamespaceFilter(BaseTestFilter, unittest.TestCase):

    filter_class = rlcompleter.NamespaceFilter

    def add_filter(self, c, f):
        return c.add_namespace_filter(f)

    def remove_filter(self, c, f):
        return c.remove_namespace_filter(f)

    def assert_filters_equal(self, c, fs):
        self.assertListEqual(c.namespace_filters, fs)

    def test_default_filter(self):
        c = self.get_completer(dict.fromkeys(['my_foo', 'their_foo']))
        self.add_filter(c, self.new_filter())
        self.assertEqual(c.complete('my_', 0), 'my_foo')

    def test_simple_filter(self):
        class SimpleFilter(self.filter_class):
            def filter(self, namespace, key, value, text, /, **options):
                return not key.startswith('_')

        c = self.get_completer(dict.fromkeys(['my_foo', '_sunder']))
        self.add_filter(c, SimpleFilter())
        self.assertEqual(c.complete('my_', 0), 'my_foo')
        self.assertEqual(c.complete('_sunder', 0), None)

    def test_chain_filters(self):

        class SkipIf(self.filter_class):
            def __init__(self, prefix):
                super().__init__()
                self.prefix = prefix

            def filter(self, namespace, key, value, text, /, **options):
                return not key.startswith(self.prefix)

        c = self.get_completer(dict.fromkeys(['my1_skip', 'my2_skip', 'my3']))
        self.add_filter(c, SkipIf('my1_skip'))
        self.add_filter(c, SkipIf('my2_skip'))

        matches = c.get_matches('my')
        self.assertNotIn('my1_skip', matches)
        self.assertNotIn('my2_skip', matches)
        self.assertIn('my3', matches)


class Object:
    pick0 = ...
    skip0 = ...
    _sunder0 = ...
    __dunder0 = ...
    __ddunder0__ = ...

    def __init__(self):
        self.pick1 = ...
        self.skip1 = ...
        self._sunder1 = ...
        self.__dunder1 = ...
        self.__ddunder1__ = ...

    def pick2(self): ...
    def skip2(self): ...
    def _sunder2(self): ...
    def __dunder2(self): ...
    def __ddunder2__(self): ...

    @property
    def pick3(self): ...
    @property
    def skip3(self): ...
    @property
    def _sunder3(self): ...
    @property
    def __dunder3(self): ...
    @property
    def __ddunder3__(self): ...

    @classmethod
    def pick4(cls): ...
    @classmethod
    def skip4(cls): ...
    @classmethod
    def _sunder4(cls): ...
    @classmethod
    def __dunder4(cls): ...
    @classmethod
    def __ddunder4__(cls): ...

    @staticmethod
    def pick5(): ...
    @staticmethod
    def skip5(): ...
    @staticmethod
    def _sunder5(): ...
    @staticmethod
    def __dunder5(): ...
    @staticmethod
    def __ddunder5__(): ...


class TestAttributeFilter(BaseTestFilter, unittest.TestCase):

    filter_class = rlcompleter.AttributeFilter

    @classmethod
    def setUpClass(cls):
        cls.objname = 'my_object'  # should not be a keyword or a built-in
        cls.prefixes = ('pick', 'skip', '_sunder',
                        '_Object__dunder', '__ddunder')

        class SkipIfContains(cls.filter_class):
            def __init__(self, prefix):
                super().__init__()
                self.prefix = prefix

            def filter(self, instance, name, value, text, /, **options):
                return self.prefix not in name

        cls.SkipIfContains = SkipIfContains

    def add_filter(self, c, f):
        return c.add_attribute_filter(f)

    def remove_filter(self, c, f):
        return c.remove_attribute_filter(f)

    def assert_filters_equal(self, c, fs):
        self.assertListEqual(c.attribute_filters, fs)

    def make_matches(self, objname, prefix):
        assert prefix in self.prefixes
        suffix = '__' if prefix == '__ddunder' else ''

        return [
            f"{objname}.{prefix}0{suffix}",   # class attribute
            f"{objname}.{prefix}1{suffix}",   # attribute
            f"{objname}.{prefix}2{suffix}()", # method
            f"{objname}.{prefix}3{suffix}",   # property
            f"{objname}.{prefix}4{suffix}()", # class method
            f"{objname}.{prefix}5{suffix}()", # static method
        ]

    def test_default_filter(self):
        c = self.get_completer({self.objname: Object()})
        self.add_filter(c, self.new_filter())

        for p in self.prefixes:
            with self.subTest(p):
                matches = c.get_matches(f'{self.objname}.{p}')
                expects = self.make_matches(self.objname, p)
                self.assertListEqual(matches, expects)

    def test_simple_filter(self):
        for p in self.prefixes:
            with self.subTest(p):
                c = self.get_completer({self.objname: Object()})
                self.add_filter(c, self.SkipIfContains(p))
                matches = c.get_matches(f'{self.objname}.{p}')
                self.assertListEqual(matches, [])

    def test_chain_filters(self):
        for r in range(len(self.prefixes)):
            for ps in itertools.combinations(self.prefixes, r=r + 2):
                c = self.get_completer({self.objname: Object()})
                # add many filters
                for p in ps:
                    self.add_filter(c, self.SkipIfContains(p))

                for p in ps:
                    with self.subTest('exclude', filters=ps, prefix=p):
                        matches = c.get_matches(f'{self.objname}.{p}')
                        self.assertListEqual(matches, [])

                # check that the remaining objects are completed
                for p in set(self.prefixes).difference(ps):
                    with self.subTest('include', filters=ps, prefix=p):
                        matches = c.get_matches(f'{self.objname}.{p}')
                        expects = self.make_matches(self.objname, p)
                        self.assertListEqual(matches, expects)


if __name__ == '__main__':
    unittest.main()
