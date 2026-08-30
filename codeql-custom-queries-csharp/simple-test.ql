/**
 * @name Simple Test Query - Find all classes
 * @description A simple query to test if CodeQL is working properly
 * @kind problem
 * @problem.severity recommendation
 * @id csharp/test/find-classes
 */

import csharp

from Class c
where c.isPublic()
select c, "Found public class: " + c.getName()
