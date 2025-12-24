/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void Colorize__Awake(Colorize_o *__this,MethodInfo *method)

{
  int32_t iVar1;
  
  if (DAT_0445a26b == '\0') {
                    /* WARNING: Subroutine does not return */
    EnsureInitializedOrSmt(&Colorize_TypeInfo);
  }
  iVar1 = UnityEngine_Shader__PropertyToID(_StringLiteral_11843,(MethodInfo *)0x0);
  Colorize_TypeInfo->static_fields->b = iVar1;
  iVar1 = UnityEngine_Shader__PropertyToID(_StringLiteral_10779,(MethodInfo *)0x0);
  Colorize_TypeInfo->static_fields->c = iVar1;
  if (DAT_0446b968 == (code *)0x0) {
    DAT_0446b968 = (code *)FindMethodAdressByName("UnityEngine.Behaviour::set_enabled(System.Boolean)",0,0);
  }
                    /* WARNING: Could not recover jumptable at 0x0327d7af. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*DAT_0446b968)(__this,0);
  return;
}
