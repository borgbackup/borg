from sphinx import addnodes
from sphinx.domains import Domain, ObjType
from sphinx.locale import l_, _
from sphinx.directives import ObjectDescription
from sphinx.domains.std import ws_re


class BorgObject(ObjectDescription):
    indextemplate = l_('%s')
    parse_node = None  # type: Callable[[GenericObject, BuildEnvironment, unicode, addnodes.desc_signature], unicode]  # NOQA

    def handle_signature(self, sig, signode):
        # type: (unicode, addnodes.desc_signature) -> unicode
        pass

    def add_target_and_index(self, name, sig, signode):
        # type: (str, str, addnodes.desc_signature) -> None
        #                  ^ ignore this one, don't insert any markup.
        # v- the human text               v- the target name
        # "borg key change-passphrase" -> "borg-key-change-passphrase"
        del name  # ignored
        targetname = sig.replace(' ', '-')
        if self.indextemplate:
            colon = self.indextemplate.find(':')
            if colon != -1:
                indextype = self.indextemplate[:colon].strip()
                indexentry = self.indextemplate[colon + 1:].strip() % (sig,)
            else:
                indextype = 'single'
                indexentry = self.indextemplate % (sig,)
            self.indexnode['entries'].append((indextype, indexentry, targetname, '', None))
        self.env.domaindata['borg']['objects'][targetname] = self.env.docname, self.objtype, sig

    def run(self):
        super().run()
        return [self.indexnode]


class BorgCommand(BorgObject):
    """
    Inserts an index entry and an anchor for a borg command.

    For example, the following snippet creates an index entry about the "borg foo-and-bar"
    command as well as a "borg-foo-and-bar" anchor (id).

        .. borg:command:: borg foo-and-bar
    """

    indextemplate = l_('%s (command)')


class BorgEnvVar(BorgObject):
    """
    Inserts an index entry and an anchor for an environment variable.
    (Currently not used)
    """

    indextemplate = l_('%s (environment variable)')


class BorgDomain(Domain):
    """Land of the Borg."""
    name = 'borg'
    label = 'Borg'
    object_types = {
        'command':   ObjType(l_('command')),
        'env_var':   ObjType(l_('env_var')),
    }
    directives = {
        'command': BorgCommand,
        'env_var': BorgEnvVar,
    }
    roles = {}
    initial_data = {
        'objects': {},  # fullname -> docname, objtype
    }

    def clear_doc(self, docname):
        # required for incremental builds
        try:
            del self.data['objects'][docname]
        except KeyError:
            pass

    def merge_domaindata(self, docnames, otherdata):
        # needed due to parallel_read_safe
        for fullname, (docname, objtype, sig) in otherdata['objects'].items():
            if docname in docnames:
                self.data['objects'][fullname] = (docname, objtype, sig)

    def get_objects(self):
        for refname, (docname, objtype, sig) in list(self.data['objects'].items()):
            yield sig, sig, objtype, docname, refname, 1


def setup(app):
    app.add_domain(BorgDomain)
    return {
        'version': 1,
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
