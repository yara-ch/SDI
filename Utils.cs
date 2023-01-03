using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using System.Reflection;
using System.IO;
using dnlib.DotNet.Emit;

namespace Yara.StringDecryptionInvoker
{
    class Utils
    {
        public static TypeDef[] GetAllNestedTypes(TypeDef type)
        {
            List<TypeDef> result = new List<TypeDef>();
            foreach (TypeDef nsType in type.NestedTypes)
            {
                if (nsType.HasNestedTypes) { result.AddRange(GetAllNestedTypes(nsType)); }
                result.Add(nsType);
            }
            return result.ToArray();
        }

        public static TypeDef[] GetAllTypes(ModuleDefMD asm)
        {
            List<TypeDef> result = new List<TypeDef>();
            foreach (TypeDef type in asm.Types)
            {
                if (type.HasNestedTypes) { result.AddRange(GetAllNestedTypes(type)); }
                result.Add(type);
            }
            return result.ToArray();
        }
    }
}
