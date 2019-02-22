.. include:: global.rst.inc
.. highlight:: none
.. _detailed_usage:

Usage
=====

.. raw:: html
   Redirecting...

   <script type="text/javascript">
   // Fixes old links which were just anchors
   var hash = window.location.hash.substring(1);

   // usage.html is empty, no content. Purely serves to implement a "correct" toctree
   // due to rST/Sphinx limitations. Refer to https://github.com/sphinx-doc/sphinx/pull/3622

   // Redirect to general docs
   if(hash == "") {
       var replaced = window.location.pathname.replace("usage.html", "usage/general.html");
       if (replaced != window.location.pathname) {
           window.location.pathname = replaced;
       }
   }
   // Fixup anchored links from when usage.html contained all the commands
   else if(hash.startsWith("borg-key") || hash == "borg-change-passphrase") {
      window.location.hash = "";
      window.location.pathname = window.location.pathname.replace("usage.html", "usage/key.html");
   }
   else if(hash.startsWith("borg-")) {
      window.location.hash = "";
      window.location.pathname = window.location.pathname.replace("usage.html", "usage/") + hash.substr(5) + ".html";
   }
   </script>

.. toctree::
   usage/general

   usage/init
   usage/create
   usage/extract
   usage/check
   usage/rename
   usage/list
   usage/diff
   usage/delete
   usage/prune
   usage/info
   usage/mount
   usage/key
   usage/upgrade
   usage/recreate
   usage/tar
   usage/serve
   usage/config
   usage/lock
   usage/benchmark

   usage/help
   usage/debug
   usage/notes
