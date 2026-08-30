/**
 * @name View AST for Contact.cshtml.cs
 * @description Displays the Abstract Syntax Tree for the Contact page model
 *              to help understand CodeQL's representation of the code
 * @kind graph
 * @id csharp/view-ast-contact
 */

import csharp

// Find elements in the Contact.cshtml.cs file
class ContactFile extends File {
  ContactFile() {
    this.getBaseName() = "Contact.cshtml.cs"
  }
}

from Element e, ContactFile f
where e.getFile() = f
select e, e.getPrimaryQlClasses()
