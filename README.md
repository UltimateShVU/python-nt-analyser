# python-nt-analyser 2023

## Авторы
Pavel Chernov (K1rch), Shevelev Viktor (UltimateShVU), Yudin Ivan(monhaim).

## Описание/Description

Анализатор трафика на интерфейсах — это утилита, которая позволяет мониторить и анализировать передачу данных через сетевые интерфейсы. Позволяет детектировать сетевые атаки, такие как DoS, ARP-спуфинг и другие проверки.
 
Наш анализатор трафика на интерфейсах имеет большой потенциал для использования в различных областях, в том числе: 
1. Оптимизация производительности сети: анализатор трафика на интерфейсах может использоваться для оптимизации производительности сети путем выявления узких мест в сетевой инфраструктуре и принятия соответствующих мер для устранения проблем. 
2. Диагностика сетевых проблем: анализатор трафика на интерфейсах может использоваться для диагностики различных проблем в сети, таких как низкая производительность или сбои в работе сети. 
3. Определение сетевых требований: анализатор трафика на интерфейсах может использоваться для определения требований к сети в зависимости от приложений и устройств, использующих сеть. 
4. Отладка сетевых приложений: анализатор трафика на интерфейсах может использоваться для отладки сетевых приложений, что позволяет выявить и исправить ошибки в их работе.

Все эти модули вы можете при желании написать самостоятельно и внедрить свой алгорим в наш код.

## Сборка и установка

1. Выполните копирование репозитория
 ```
 git clone git@github.com:UltimateShVU/python-nt-analyser.git
 ```

ВНИМАНИЕ:
От Вас потребуются права root, чтобы интегрировать анализатор в свою систему !

2. Запустите 
 ```
 1. sudo su
 2. python3 main.py -i lo # запуск анализатора на loopback-интерфейсе
 ```

4. Проверка работоспособности анализатора.

*Включите функцию записи трафика в дамп, и если размер дампа со временем будет увеличиваться, то анализатор работает.*



5. <b>Остановите работу</b>

*Отправьте анализатору сигнал `CTRL+C` - чтобы нормально завершить работу.*



## Дополнительно
Если вы хотите сделать замечание, исправить найденный баг, предложить улучшение -
делайте merge-request. 
Названия ветки давайте таким образом:
bugfix-1.1 (если это первый найденный баг за проект), аналогично с фичами и модификациями (первое число - версия проекта, второе - номер исправленного бага, в данном случае).

Аналогично с фичами и модификациями:

feature-1.2

enhancement-1.3

Обязательно оставляйте комментарии о проделанной работе.
```
git commit -m "commit message"
```
В поле "commit message" пишете свой комментарий, где первое слово коммита - bug, enhancement, feature, затем идёт порядковый номер и внесенные правки. 

bug: #0 fixed some shit

feature: #3 added module for traffic-analysis