.. include:: global.rst.inc
.. highlight:: none
.. _detailed_usage:

Usage
=====

.. raw:: html
   Redirecting...

   <script type="text/javascript">
   // Fixes old links that were just anchor fragments
   var hash = window.location.hash.substring(1);

   // usage.html is empty; it contains no content. It purely serves to implement a "correct" toctree
   // due to reST/Sphinx limitations. Refer to https://github.com/sphinx-doc/sphinx/pull/3622

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

   usage/repo-create
   usage/repo-space
   usage/repo-list
   usage/repo-info
   usage/repo-compress
   usage/repo-delete
   usage/serve
   usage/version
   usage/compact
   usage/lock
   usage/key

   usage/create
   usage/extract
   usage/check
   usage/list
   usage/tag
   usage/rename
   usage/diff
   usage/delete
   usage/prune
   usage/undelete
   usage/info
   usage/analyze
   usage/mount
   usage/recreate
   usage/tar

   usage/transfer
   usage/benchmark

   usage/help
   usage/debug
   usage/notes
