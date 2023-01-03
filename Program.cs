using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using System.IO;
using System.Threading;
using dnlib.DotNet.Emit;
using System.Reflection;
using System.Diagnostics;
using System.Windows.Forms;
using dnlib.DotNet.Writer;

namespace Yara.StringDecryptionInvoker
{
    class Program
    {
        public static string path;
        public static Assembly app;

        public static MethodInfo refStringMethod = null;
        public static ModuleDefMD asm;
        public static MethodDef stringMethod = null;

        private static uint rid = uint.MaxValue;

        static string ResolveString(object[] parameters)
        {
            return (string)refStringMethod.Invoke(null, parameters);
        }

        static void Exit(int xPos = -1, int yPos = -1)
        {
            Console.ResetColor();
            Console.Write("\n Press any key to exit...");
            Console.CursorVisible = false;
            Console.SetCursorPosition(xPos == -1 ? Console.CursorLeft : xPos, yPos == -1 ? Console.CursorTop : yPos);
            Console.ReadKey();
            Application.Exit();
        }

        static void ShowError(string message, bool exit = false)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message);
            Console.ResetColor();
            if (exit) { Exit(); }
        }

        static public void Save()
        {
            string file = Path.GetFileNameWithoutExtension(path) + "-SDI" + Path.GetExtension(path);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n Saving '" + file + "'...");
            ModuleWriterOptions moduleWriterOptions = new ModuleWriterOptions(asm);
            moduleWriterOptions.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
            moduleWriterOptions.Logger = DummyLogger.NoThrowInstance;
            asm.Write(file, moduleWriterOptions);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("'" + file + "' saved!");
            Exit();
        }

        static void Main(string[] args)
        {
            Console.Title = "Yara.SDI v1.0";

            if (args.Length == 0) { ShowError("\n No input file set!", true); }

            path = Path.GetFullPath(args[0]);
            if (!File.Exists(path)) { ShowError("\n File not found!", true); }

            if (args.Length > 1)
            {
                try   { rid = uint.Parse(args[1]); }
                catch { ShowError("\n [Arguments]: '" + args[1] + "' is not a valid RID!"); }
            }

            app = Assembly.LoadFile(path);
            asm = ModuleDefMD.Load(path);

            if (rid == uint.MaxValue)
            {
                while (true)
                {
                    Console.Write("\n String Decryption Method RID: ");
                    try
                    {
                        uint.TryParse(Console.ReadLine(), out rid);
                        if (rid == 0) { throw new Exception("Invalid RID - Invalid Input"); }
                        stringMethod = asm.ResolveMethod(rid);
                        if (stringMethod == null) { throw new Exception("Invalid RID - Method does not exist"); }
                        break;
                    }
                    catch (Exception ex)
                    {
                        ShowError(" " + ex.Message);
                        Thread.Sleep(1000);
                    }
                    Console.ResetColor();
                    Console.Clear();
                }
            }
            
            Console.CursorVisible = false;

            try
            {
                foreach (Type type in app.GetTypes())
                {
                    if (type.MetadataToken == stringMethod.DeclaringType.MDToken.Raw)
                    {
                        foreach (MethodInfo method in type.GetMethods((BindingFlags)0x38))
                        {
                            if (method.MetadataToken == stringMethod.MDToken.Raw)
                            {
                                refStringMethod = method;
                                break;
                            }
                        }
                    }
                    if (refStringMethod != null) { break; }
                }
            }
            catch (ReflectionTypeLoadException ex)
            {
                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("\n Error loading Referenced Modules!");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write("\n |- ");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Try putting SDI in the same folder as the target.\n");
                AssemblyName[] asmNames = app.GetReferencedAssemblies();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(" --- Referenced Modules [" + asmNames.Length + "] ---");
                foreach (AssemblyName name in asmNames)
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(" |- ");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(name.Name);
                    Console.ResetColor();
                }
                Exit(0,0);
                return;
            }
            catch
            {
                throw;
            }

            foreach (TypeDef type in Utils.GetAllTypes(asm))
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions.Count == 0) { continue; }
                    for (int x = 0; x < method.Body.Instructions.Count; x++)
                    {
                        Instruction inst = method.Body.Instructions[x];
                        if ((inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt) &&
                            inst.Operand is MethodDef &&
                            (MethodDef)inst.Operand == stringMethod)
                        {
                            object[] parameters = new object[stringMethod.Parameters.Count];
                            bool invoke = true;
                            for (int y = 0; y < stringMethod.Parameters.Count; y++)
                            {
                                Instruction paramInst = method.Body.Instructions[(x-1)-y];
                                if (paramInst.IsLdcI4()) { parameters[y] = paramInst.GetLdcI4Value(); }
                                else
                                {
                                    if (paramInst.Operand == null)
                                    {
                                        ShowError(" [Not Recovered]: IL_" + method.Body.Instructions.IndexOf(paramInst).ToString("X4") + " at RID: " + method.Rid);
                                        invoke = false;
                                        break;
                                    }
                                    parameters[y] = paramInst.Operand;
                                }
                            }
                            if (invoke)
                            {
                                for (int y = 0; y < parameters.Length+1; y++)
                                {
                                    method.Body.Instructions.RemoveAt(x-2);
                                }
                                try
                                {
                                    Array.Reverse(parameters);
                                    string ogStr = ResolveString(parameters);
                                    method.Body.Instructions.Insert(x-2,new Instruction(OpCodes.Ldstr, ogStr));
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.WriteLine("[Recovered]: " + '"' + ogStr + '"');
                                }
                                catch
                                {
                                    ShowError(" [Not Recovered]: IL_" + x.ToString("X4") + " at RID: " + method.Rid);
                                }
                            }
                        }
                    }
                }
            }
            Save();
        }
    }
}
