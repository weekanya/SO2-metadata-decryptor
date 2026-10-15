# Metadata-Decryptor

Достаёт global-metadata.dat из libunity.so Standoff 2 версии 1.0.0 (arm64, метадата v31) и патчит библиотеку, чтобы Il2CppDumper выдал dump.cs с адресами методов.

- `metadata_decryptor.py` собирает стандартный global-metadata.dat из перемешанных данных в .rodata
- `libunity_patch.py` делает копию libunity.so с нормальными CodeRegistration и MetadataRegistration
- `global-metadata.dat` готовый результат для версии 1.0.0

## Защита

Заголовок метадаты разбит на слова, лежащие в .rodata вперемешку, поля в таблицах (методы, свойства, события, типы) переставлены. Скрипт находит слова по содержимому, восстанавливает порядок секций по цепочке offset + size и переписывает таблицы в формат v31.

CodeRegistration и MetadataRegistration слиты в один блок из 29 слов и перемешаны, у CodeGenModule, Il2CppType, GenericClass, ArrayType, methodSpecs и genericMethodTable переставлены поля. Релокации применяются при загрузке, поэтому патчер записывает их результат в данные, обнуляет DT_RELASZ и кладёт стандартные структуры в новый сегмент.

## Запуск

Нужны python3 и numpy.

    python3 metadata_decryptor.py libunity.so -o global-metadata.dat
    python3 libunity_patch.py libunity.so global-metadata.dat libunity_patched.so

Патчер печатает адреса CodeRegistration и MetadataRegistration. Дальше Il2CppDumper на libunity_patched.so и метадате, адреса вводить вручную, если сам не найдёт:

    dotnet Il2CppDumper.dll libunity_patched.so global-metadata.dat out/

Generate struct требует много памяти: на слабом устройстве либо подними лимит (DOTNET_GCHeapHardLimit), либо поставь в config.json дампера "GenerateStruct": false.

## Проверено

Standoff 2 версии 1.0.0: v31, 34466 типов, 476 сборок. Il2CppDumper 6.7.46 проходит все три этапа без ошибок: dump.cs, Generate struct (il2cpp.h, script.json) и Generate dummy dll. По сравнению с другим дампом той же версии совпали адреса 168252 методов, все типы, поля и методы там есть. Смещения полей у структур на 0x10 меньше, это дампер вычитает заголовок объекта.

## Ограничения

- Работает только на версии 1.0.0, на ней всё проверялось и сверялось. На других версиях работа не гарантируется: патчер привязан к раскладке этой сборки и при несовпадении остановится с ошибкой.
- У ~17 тысяч generic-методов и делегатов RVA -1: в файле нули, заглушки подставляет игра при запуске.
- Два модуля (Unity.Collections.LowLevel.ILSupport.dll, UnityEngine.Purchasing.AppleCore.dll) лежат в .bss и пусты.
- rgctx обнулены, у thread-static полей смещение 0xFFFFFFFFFFFFFFFF.
